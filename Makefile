SHELL := /bin/bash
TF    := terraform -chdir=terraform
NAME  ?= client1

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- build

certs: ## Create private CA, VPN server, web and client1 certificates
	scripts/pki.sh init

bundle: ## Build the offline app bundle (code + Python wheels)
	scripts/build-bundle.sh

# ---------------------------------------------------------------- deploy

init: ## terraform init
	$(TF) init

plan: certs bundle ## terraform plan
	$(TF) plan -out=tfplan

apply: ## Apply the saved plan
	$(TF) apply tfplan

deploy: certs bundle init ## One-shot: certs + bundle + init + apply
	$(TF) apply
	@echo; echo "Next: confirm the SNS email, then run 'make vpn-config'"

vpn-config: ## Build vpn-clients/$(NAME).ovpn (NAME=client1)
	scripts/make-ovpn.sh $(NAME)

client: ## Issue a new VPN client certificate (NAME=alice)
	scripts/pki.sh client $(NAME)
	scripts/make-ovpn.sh $(NAME)

revoke: ## Revoke a VPN client certificate and enforce the CRL (NAME=alice)
	scripts/pki.sh revoke $(NAME)
	scripts/pki.sh push-crl

outputs: ## Show deployment outputs
	$(TF) output

# ---------------------------------------------------------------- verify

smoke: ## End-to-end security checks (connect the VPN first)
	scripts/smoke-test.sh

smoke-novpn: ## Prove the app is unreachable without the VPN
	scripts/smoke-test.sh --no-vpn

test: ## Unit tests (app + Lambdas, AWS mocked with moto)
	python3 -m pytest -q tests

lint: ## Formatting, validation and static analysis
	$(TF) fmt -check -recursive
	$(TF) validate
	ruff check app lambdas tests
	@command -v checkov >/dev/null && checkov -d terraform --config-file .checkov.yaml --quiet || echo "checkov not installed (pip install checkov)"

# ---------------------------------------------------------------- operate

demo-alert: ## Fire a test alarm (email in ~1 min)
	scripts/demo.sh alert

demo-outage: ## Stop the app to trigger the availability alarm
	scripts/demo.sh outage

demo-restore: ## Restart the app
	scripts/demo.sh restore

demo-sg-guard: ## Open SSH to the world and watch it get auto-revoked
	scripts/demo.sh sg-guard

shell: ## Shell on the web server through SSM (no SSH)
	scripts/demo.sh shell

destroy: ## Tear everything down (stops all charges)
	$(TF) destroy

.PHONY: help certs bundle init plan apply deploy vpn-config client revoke outputs smoke smoke-novpn test lint demo-alert demo-outage demo-restore demo-sg-guard shell destroy
