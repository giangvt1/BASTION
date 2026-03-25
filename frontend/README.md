# BASTION Frontend — SOC Dashboard

Real-time Security Operations Center dashboard built with React, TypeScript, and Vite.

## Tech Stack

- **React 19** + **TypeScript 5.9**
- **Vite 8** (dev server & build)
- **TailwindCSS 3** (styling)
- **React Router** (SPA routing)
- **React Markdown** + **remark-gfm** (report rendering)

## Pages

| Page | Route | Description |
|------|-------|-------------|
| **SOC Dashboard** | `/` | Main analyst workspace — file upload, pipeline status, report viewer, IOC table |
| **Orchestrator** | `/orchestrator` | Real-time multi-agent orchestration and pipeline state viewer |
| **Metrics** | `/metrics` | System performance metrics, MTTR, false positive rates |

## Components

| Component | Purpose |
|-----------|---------|
| `Header` | Top navigation bar with branding and status indicators |
| `Sidebar` | Left navigation with page links and quick actions |
| `GraphView` | LangGraph agent workflow visualization (node graph) |
| `RightPanel` | Context panel for IOC details, agent logs, and enrichment data |
| `Footer` | Status bar with connection state and version info |

## API Integration

The frontend connects to the backend API server (`scripts/api_server.py`) via REST endpoints defined in `src/services/api.ts`.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze` | POST | Submit security artifacts for analysis |
| `/results/{task_id}` | GET | Retrieve analysis results |
| `/stream/{task_id}` | SSE | Real-time pipeline progress streaming |

## Getting Started

```bash
# Install dependencies
npm install

# Start dev server (connects to backend on port 8001)
npm run dev

# Build for production
npm run build
```

- **Dev URL:** http://localhost:5173
- **Backend API:** http://localhost:8001 (must be running)

## Development

```bash
npm run lint       # ESLint checks
npm run build      # Production build (TypeScript check + Vite)
npm run preview    # Preview production build
```
