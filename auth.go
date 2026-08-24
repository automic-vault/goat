package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/adrg/xdg"
	"github.com/urfave/cli/v3"
)

var ErrNoAuthSession = errors.New("no auth session found")

const avCredentialMarker = "@av"

type authSecrets struct {
	Password     string `json:"password"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"session_token"`
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

type AuthSession struct {
	DID          syntax.DID `json:"did"`
	Password     string     `json:"password"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"session_token"`
	PDS          string     `json:"pds"`
}

func persistAuthSession(sess *AuthSession) error {
	fPath, err := xdg.StateFile("goat/auth-session.json")
	if err != nil {
		return err
	}

	secrets := authSecrets{sess.Password, sess.AccessToken, sess.RefreshToken}
	secretBytes, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	if err := avCredential("store", sess.DID.String(), sess.PDS, secretBytes); err != nil {
		return err
	}
	metadata := *sess
	metadata.Password = avCredentialMarker
	metadata.AccessToken = avCredentialMarker
	metadata.RefreshToken = avCredentialMarker

	authBytes, err := json.MarshalIndent(&metadata, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(fPath), ".auth-session.json.av-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(authBytes); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, fPath)
}

func loadAuthMetadataFile() (*AuthSession, error) {
	fPath, err := xdg.SearchStateFile("goat/auth-session.json")
	if err != nil {
		return nil, ErrNoAuthSession
	}

	fBytes, err := os.ReadFile(fPath)
	if err != nil {
		return nil, err
	}

	var sess AuthSession
	if err := decodeStrictJSON(fBytes, &sess); err != nil {
		return nil, err
	}
	if sess.Password != avCredentialMarker || sess.AccessToken != avCredentialMarker || sess.RefreshToken != avCredentialMarker {
		return nil, errors.New("plaintext goat credentials are disabled; run `av harden goat`")
	}
	return &sess, nil
}

func loadAuthSessionFile() (*AuthSession, error) {
	sess, err := loadAuthMetadataFile()
	if err != nil {
		return nil, err
	}
	secretBytes, err := avCredentialOutput("get", sess.DID.String(), sess.PDS, nil)
	if err != nil {
		return nil, err
	}
	var secrets authSecrets
	if err := decodeStrictJSON(secretBytes, &secrets); err != nil {
		return nil, err
	}
	if secrets.Password == "" || secrets.AccessToken == "" || secrets.RefreshToken == "" {
		return nil, errors.New("Automic Vault returned incomplete goat credentials")
	}
	sess.Password = secrets.Password
	sess.AccessToken = secrets.AccessToken
	sess.RefreshToken = secrets.RefreshToken
	return sess, nil
}

func avCredential(action, did, pds string, input []byte) error {
	_, err := avCredentialOutput(action, did, pds, input)
	return err
}

func avCredentialOutput(action, did, pds string, input []byte) ([]byte, error) {
	cmd := exec.Command("/usr/local/bin/av", "goat-credential", action, did, pds)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	var output bytes.Buffer
	output.Grow(4096)
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("Automic Vault goat credential helper failed: %w", err)
	}
	if output.Len() > 64*1024 {
		return nil, errors.New("Automic Vault returned oversized goat credentials")
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func authRefreshCallback(ctx context.Context, data atclient.PasswordSessionData) {
	fmt.Println("auth refresh callback")
	sess, _ := loadAuthSessionFile()
	if sess == nil {
		sess = &AuthSession{}
	}

	sess.DID = data.AccountDID
	sess.AccessToken = data.AccessToken
	sess.RefreshToken = data.RefreshToken
	sess.PDS = data.Host

	if err := persistAuthSession(sess); err != nil {
		slog.Warn("failed to save refreshed auth session data", "err", err)
	}
}

func loginOrLoadAuthClient(ctx context.Context, cmd *cli.Command) (*atclient.APIClient, error) {

	// if user/pass provided in env vars, login as emphemeral session with those
	username := cmd.String("username")
	password := cmd.String("password")
	if username != "" && password != "" {
		dir := configDirectory(cmd.String("plc-host"))
		atid, err := syntax.ParseAtIdentifier(username)
		if err != nil {
			return nil, err
		}
		return atclient.LoginWithPassword(ctx, dir, atid, password, "", nil)
	}

	// otherwise try loading from disk
	return loadAuthClient(ctx, cmd)
}

func loadAuthClient(ctx context.Context, cmd *cli.Command) (*atclient.APIClient, error) {

	sess, err := loadAuthSessionFile()
	if err != nil {
		return nil, err
	}

	// first try to resume session
	client := atclient.ResumePasswordSession(atclient.PasswordSessionData{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		AccountDID:   sess.DID,
		Host:         sess.PDS,
	}, authRefreshCallback)

	// check that auth is working
	_, err = comatproto.ServerGetSession(ctx, client)
	if nil == err {
		return client, nil
	}

	// otherwise try new auth session using saved password
	dir := configDirectory(cmd.String("plc-host"))
	return atclient.LoginWithPassword(ctx, dir, sess.DID.AtIdentifier(), sess.Password, "", authRefreshCallback)
}

func wipeAuthSession() error {
	fPath, err := xdg.SearchStateFile("goat/auth-session.json")
	if err != nil {
		fmt.Printf("no auth session found (already logged out)\n")
		return nil
	}
	sess, err := loadAuthMetadataFile()
	if err != nil {
		return err
	}
	if err := avCredential("forget", sess.DID.String(), sess.PDS, nil); err != nil {
		return err
	}
	return os.Remove(fPath)
}
