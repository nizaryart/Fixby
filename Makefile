SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
export PATH := $(CURDIR)/.tools/bin:$(PATH)

IMAGE ?= vulntrack
TAG ?= dev
SKIP := --skip-dirs .venv --skip-dirs .tools --skip-dirs infra/terraform/.terraform

.PHONY: tools test sast-rules sast secrets iac build image-scan sbom deploy smoke persistence clean

tools:
	scripts/install-tools.sh

test:
	python -m pytest -q

sast-rules:
	for rule in .semgrep/*.yml; do semgrep --test --config "$$rule" "$${rule%.yml}.py"; done

sast: sast-rules
	semgrep scan --metrics=off --config p/python --config .semgrep/ --error

secrets:
	gitleaks git --redact --no-banner -v .

iac:
	terraform -chdir=infra/terraform fmt -check -diff
	terraform -chdir=infra/terraform init -backend=false -input=false -lockfile=readonly
	terraform -chdir=infra/terraform validate
	helm lint helm/vulntrack --set image.tag=ci
	trivy config --exit-code 1 --severity HIGH,CRITICAL --helm-set image.tag=ci $(SKIP) .
	cd infra/ansible && ansible-lint --profile production harden.yml
	actionlint .github/workflows/*.yml

build:
	docker build --label org.opencontainers.image.revision=$(TAG) -t $(IMAGE):$(TAG) .
	docker save -o image.tar $(IMAGE):$(TAG)

image-scan:
	trivy image --input image.tar --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed

sbom:
	trivy image --input image.tar --format cyclonedx --output sbom.cdx.json

deploy:
	TAG=$(TAG) scripts/deploy-kind.sh

smoke:
	scripts/with-port-forward.sh scripts/smoke-test.sh http://127.0.0.1:8080

persistence:
	scripts/check-persistence.sh

clean:
	-kind delete cluster --name vulntrack
	rm -f image.tar sbom.cdx.json
