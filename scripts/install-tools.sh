#!/usr/bin/env bash
# Installs pinned tool versions into .tools/bin and refuses any download whose SHA-256 does not match.
set -euo pipefail

BIN_DIR="${TOOLS_DIR:-$(pwd)/.tools/bin}"
mkdir -p "$BIN_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

declare -A URL SHA FORMAT
URL[trivy]="https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz"
SHA[trivy]="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
FORMAT[trivy]="tar"
URL[gitleaks]="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
SHA[gitleaks]="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
FORMAT[gitleaks]="tar"
URL[kind]="https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64"
SHA[kind]="aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
FORMAT[kind]="bin"
URL[kubectl]="https://dl.k8s.io/release/v1.37.2/bin/linux/amd64/kubectl"
SHA[kubectl]="c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4"
FORMAT[kubectl]="bin"
URL[helm]="https://get.helm.sh/helm-v4.3.2-linux-amd64.tar.gz"
SHA[helm]="d1c0278d46beab79582d7e50f5b3dc206944ba8e577cde618513fd07daa53983"
FORMAT[helm]="tar"
URL[terraform]="https://releases.hashicorp.com/terraform/1.17.2/terraform_1.17.2_linux_amd64.zip"
SHA[terraform]="e6f16b2f0b137ee5729caa8c4e79a3bae4ee261acd198a1fcfa8584a6296605b"
FORMAT[terraform]="zip"
URL[actionlint]="https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
SHA[actionlint]="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
FORMAT[actionlint]="tar"

install_tool() {
  local name="$1" file="$WORK/$1.download"
  [[ -n "${URL[$name]:-}" ]] || { echo "unknown tool: $name" >&2; exit 2; }
  curl -fsSL --retry 3 -o "$file" "${URL[$name]}"
  echo "${SHA[$name]}  $file" | sha256sum --check --quiet
  case "${FORMAT[$name]}" in
    bin) install -m 0755 "$file" "$BIN_DIR/$name" ;;
    zip) unzip -q -o "$file" "$name" -d "$WORK" && install -m 0755 "$WORK/$name" "$BIN_DIR/$name" ;;
    tar)
      tar -xzf "$file" -C "$WORK"
      install -m 0755 "$(find "$WORK" -type f -name "$name" -perm -u+x | head -n1)" "$BIN_DIR/$name"
      ;;
  esac
  echo "installed $name -> $BIN_DIR/$name"
}

tools=("$@")
[[ ${#tools[@]} -gt 0 ]] || tools=(trivy gitleaks kind kubectl helm terraform actionlint)
for tool in "${tools[@]}"; do install_tool "$tool"; done
[[ -z "${GITHUB_PATH:-}" ]] || echo "$BIN_DIR" >> "$GITHUB_PATH"
