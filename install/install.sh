#!/bin/sh
set -e

REPO="sladjanstojcic/poirot"
INSTALL_DIR="${POIROT_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${POIROT_VERSION:-latest}"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) os="linux" ;;
  darwin) os="darwin" ;;
  msys*|mingw*|cygwin*) os="windows" ;;
  *)
    echo "poirot: unsupported OS: $os" >&2
    exit 1
    ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "poirot: unsupported arch: $arch" >&2
    exit 1
    ;;
esac

ext=""
[ "$os" = "windows" ] && ext=".exe"
artifact="poirot-${os}-${arch}${ext}"

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep -E '"tag_name"' | head -1 | cut -d'"' -f4)"
  if [ -z "$VERSION" ]; then
    echo "poirot: could not resolve latest version" >&2
    exit 1
  fi
fi

url="https://github.com/$REPO/releases/download/$VERSION/$artifact"
sum_url="$url.sha256"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "poirot: downloading $artifact ($VERSION)"
curl -fsSL "$url" -o "$tmp/$artifact"
curl -fsSL "$sum_url" -o "$tmp/$artifact.sha256"

echo "poirot: verifying checksum"
if command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c "$artifact.sha256" >/dev/null)
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c "$artifact.sha256" >/dev/null)
else
  echo "poirot: need shasum or sha256sum to verify checksums" >&2
  exit 1
fi

if [ "${POIROT_VERIFY_SIGSTORE:-0}" = "1" ]; then
  if command -v cosign >/dev/null 2>&1; then
    echo "poirot: verifying Sigstore signature"
    curl -fsSL "$url.sigstore" -o "$tmp/$artifact.sigstore"
    cosign verify-blob \
      --bundle "$tmp/$artifact.sigstore" \
      --certificate-identity-regexp "https://github.com/$REPO/.github/workflows/release.yml@.*" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$tmp/$artifact" >/dev/null
  else
    echo "poirot: POIROT_VERIFY_SIGSTORE=1 but cosign was not found on PATH" >&2
    exit 1
  fi
fi

mkdir -p "$INSTALL_DIR"
mv "$tmp/$artifact" "$INSTALL_DIR/poirot$ext"
chmod +x "$INSTALL_DIR/poirot$ext"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo
    echo "Add to PATH:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo
    ;;
esac

echo "poirot: installed $VERSION -> $INSTALL_DIR/poirot$ext"
echo "poirot: run 'poirot --version' to confirm"
