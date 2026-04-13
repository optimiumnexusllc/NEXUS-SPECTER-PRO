# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS SPECTER PRO — Makefile                               ║
# ║  by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com          ║
# ╚══════════════════════════════════════════════════════════════╝

.PHONY: all install dev test lint format typecheck clean \
        docker-build docker-up docker-down docker-logs \
        k8s-deploy k8s-teardown dashboard worker \
        reports-clean session-clean help

NSP_VERSION   := 1.2.0-SPECTER
PYTHON        := python3
PIP           := pip3
DOCKER_IMAGE  := optimiumnexus/nexus-specter-pro
K8S_NAMESPACE := nexus-specter-pro

# ── Colours ────────────────────────────────────────────────────────────────
CYAN   := \033[0;36m
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
PURPLE := \033[0;35m
NC     := \033[0m

# ── Banner ─────────────────────────────────────────────────────────────────
define BANNER
	@echo ""
	@echo "$(PURPLE)⚡ NEXUS SPECTER PRO v$(NSP_VERSION)$(NC)"
	@echo "$(CYAN)   by OPTIMIUM NEXUS LLC$(NC)"
	@echo ""
endef

# ── Default ────────────────────────────────────────────────────────────────
all: help

# ── Installation ───────────────────────────────────────────────────────────
install: ## Install production dependencies
	$(BANNER)
	@echo "$(CYAN)📦 Installing production dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PYTHON) setup.py install
	@echo "$(GREEN)✅ Installation complete$(NC)"

dev: ## Install development dependencies (includes testing, linting)
	$(BANNER)
	@echo "$(CYAN)🔧 Installing dev dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"
	pre-commit install
	@echo "$(GREEN)✅ Dev setup complete$(NC)"

# ── Testing ────────────────────────────────────────────────────────────────
test: ## Run all tests (unit + integration)
	$(BANNER)
	@echo "$(CYAN)🧪 Running test suite...$(NC)"
	$(PYTHON) -m pytest tests/ -v --tb=short \
		--cov=nsp --cov-report=term-missing \
		--cov-report=html:reports/coverage \
		-x
	@echo "$(GREEN)✅ Tests complete$(NC)"

test-unit: ## Run unit tests only
	@echo "$(CYAN)🧪 Unit tests...$(NC)"
	$(PYTHON) -m pytest tests/unit/ -v --tb=short

test-integration: ## Run integration tests only
	@echo "$(CYAN)🔗 Integration tests...$(NC)"
	$(PYTHON) -m pytest tests/integration/ -v --tb=short -x

test-coverage: ## Generate HTML coverage report
	$(PYTHON) -m pytest tests/ --cov=nsp \
		--cov-report=html:reports/coverage \
		--cov-fail-under=60
	@echo "$(GREEN)Coverage report: reports/coverage/index.html$(NC)"

# ── Code Quality ───────────────────────────────────────────────────────────
lint: ## Run ruff linter
	@echo "$(CYAN)🔍 Linting...$(NC)"
	$(PYTHON) -m ruff check nsp/ --fix
	@echo "$(GREEN)✅ Lint complete$(NC)"

format: ## Format code with black + ruff
	@echo "$(CYAN)✨ Formatting...$(NC)"
	$(PYTHON) -m black nsp/ dashboard/ tests/ --line-length 100
	$(PYTHON) -m ruff check nsp/ --fix --select I
	@echo "$(GREEN)✅ Format complete$(NC)"

typecheck: ## Run mypy type checking
	@echo "$(CYAN)🔎 Type checking...$(NC)"
	$(PYTHON) -m mypy nsp/ --ignore-missing-imports --no-error-summary
	@echo "$(GREEN)✅ Types OK$(NC)"

qa: lint typecheck test-unit ## Quick QA: lint + types + unit tests
	@echo "$(GREEN)✅ QA passed$(NC)"

# ── Docker ─────────────────────────────────────────────────────────────────
docker-build: ## Build Docker image
	$(BANNER)
	@echo "$(CYAN)🐳 Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE):latest \
	             -t $(DOCKER_IMAGE):$(NSP_VERSION) .
	@echo "$(GREEN)✅ Image built: $(DOCKER_IMAGE):$(NSP_VERSION)$(NC)"

docker-up: ## Start full stack (NSP + PostgreSQL + Redis + Nuclei + MSF)
	$(BANNER)
	@echo "$(CYAN)🚀 Starting NEXUS SPECTER PRO stack...$(NC)"
	docker-compose up -d
	@echo ""
	@echo "$(GREEN)✅ Stack running!$(NC)"
	@echo "   Dashboard  →  http://localhost:8080"
	@echo "   API Docs   →  http://localhost:8080/docs"
	@echo "   WebSocket  →  ws://localhost:8080/ws"

docker-down: ## Stop all containers
	@echo "$(YELLOW)⏹  Stopping NSP stack...$(NC)"
	docker-compose down
	@echo "$(GREEN)✅ Stack stopped$(NC)"

docker-logs: ## Tail logs from all containers
	docker-compose logs -f --tail=100

docker-restart: docker-down docker-up ## Restart full stack

docker-push: docker-build ## Push image to Docker Hub
	@echo "$(CYAN)📤 Pushing to Docker Hub...$(NC)"
	docker push $(DOCKER_IMAGE):latest
	docker push $(DOCKER_IMAGE):$(NSP_VERSION)

# ── Kubernetes ─────────────────────────────────────────────────────────────
k8s-deploy: ## Deploy to Kubernetes
	$(BANNER)
	@echo "$(CYAN)☸️  Deploying to Kubernetes (namespace: $(K8S_NAMESPACE))...$(NC)"
	kubectl apply -f deployment/kubernetes/
	kubectl rollout status deployment/nsp-core -n $(K8S_NAMESPACE) --timeout=180s
	@echo "$(GREEN)✅ Kubernetes deploy complete$(NC)"

k8s-status: ## Show Kubernetes pod status
	kubectl get pods -n $(K8S_NAMESPACE)

k8s-logs: ## Tail Kubernetes logs
	kubectl logs -f deployment/nsp-core -n $(K8S_NAMESPACE)

k8s-teardown: ## Remove all Kubernetes resources
	@echo "$(RED)⚠  Removing K8s resources...$(NC)"
	kubectl delete namespace $(K8S_NAMESPACE) --ignore-not-found
	@echo "$(GREEN)✅ K8s resources removed$(NC)"

# ── Run Modes ──────────────────────────────────────────────────────────────
dashboard: ## Start NSP dashboard (development mode)
	@echo "$(CYAN)🖥  Starting dashboard on http://localhost:8080$(NC)"
	uvicorn dashboard.backend.main_v2:app \
		--host 0.0.0.0 --port 8080 --reload

worker: ## Start Celery worker
	@echo "$(CYAN)⚙  Starting Celery worker...$(NC)"
	celery -A nsp.core.celery_tasks worker \
		--loglevel=info --concurrency=4 -Q missions,phases,maintenance

scheduler: ## Start Celery beat scheduler
	@echo "$(CYAN)🕐 Starting Celery scheduler...$(NC)"
	celery -A nsp.core.celery_tasks beat --loglevel=info

# ── Mission Shortcuts ──────────────────────────────────────────────────────
scan-black-box: ## Run a quick black box scan (TARGET=example.com)
	@[ "$(TARGET)" ] || (echo "$(RED)❌ Set TARGET=example.com$(NC)"; exit 1)
	$(PYTHON) nsp_cli.py --mode black_box --target $(TARGET) \
		--output ./reports/ --verbose

scan-cloud: ## Run a cloud audit (PROVIDER=aws)
	@[ "$(TARGET)" ] || (echo "$(RED)❌ Set TARGET=example.com$(NC)"; exit 1)
	$(PYTHON) nsp_cli.py --mode cloud_audit --target $(TARGET) \
		--provider $(or $(PROVIDER),aws) --output ./reports/

# ── Cleanup ────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts, cache, temp files
	@echo "$(YELLOW)🧹 Cleaning...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .eggs/ .mypy_cache/ .pytest_cache/ .ruff_cache/
	@echo "$(GREEN)✅ Clean$(NC)"

reports-clean: ## Remove all generated reports
	@echo "$(YELLOW)🗑  Clearing reports/...$(NC)"
	rm -rf reports/*.html reports/*.pdf reports/*.json
	@echo "$(GREEN)✅ Reports cleared$(NC)"

session-clean: ## Remove all NSP session files
	@echo "$(YELLOW)🗑  Clearing session files...$(NC)"
	rm -f /tmp/nsp_sessions/*.nsp
	@echo "$(GREEN)✅ Sessions cleared$(NC)"

# ── Updates ────────────────────────────────────────────────────────────────
update-nuclei: ## Update Nuclei templates
	@echo "$(CYAN)🔄 Updating Nuclei templates...$(NC)"
	nuclei -update-templates
	@echo "$(GREEN)✅ Templates updated$(NC)"

update-deps: ## Update Python dependencies
	@echo "$(CYAN)🔄 Updating dependencies...$(NC)"
	$(PIP) install --upgrade -r requirements.txt
	@echo "$(GREEN)✅ Dependencies updated$(NC)"

# ── Info ───────────────────────────────────────────────────────────────────
version: ## Show NSP version
	@echo "NEXUS SPECTER PRO v$(NSP_VERSION) — by OPTIMIUM NEXUS LLC"

status: ## Show current stack status
	@echo "$(CYAN)📊 Stack Status:$(NC)"
	@docker-compose ps 2>/dev/null || echo "  Docker stack not running"
	@echo ""
	@echo "$(CYAN)🐍 Python:$(NC) $(shell $(PYTHON) --version)"
	@echo "$(CYAN)🐳 Docker:$(NC) $(shell docker --version 2>/dev/null || echo 'not found')"

help: ## Show this help
	$(BANNER)
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-22s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make install              Install NSP"
	@echo "  make docker-up            Start full stack"
	@echo "  make test                 Run all tests"
	@echo "  make scan-black-box TARGET=example.com"
	@echo ""
	@echo "$(PURPLE)OPTIMIUM NEXUS LLC | contact@optimiumnexus.com$(NC)"
