.PHONY: dev frontend backend

dev: ## Start both backend (Django) and frontend (Vite) dev servers
	./run_dev.sh

frontend: ## Start frontend only
	cd frontend && npm run dev

backend: ## Start backend only
	python3 manage.py runserver 8000
