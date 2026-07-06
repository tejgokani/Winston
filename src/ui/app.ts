import express, { type Express } from "express";
import { fileURLToPath } from "node:url";
import { generateReport as renderReport } from "../pipeline/reportGenerator.js";
import { loadGraphForRepo } from "../storage/graphStore.js";
import { listScans } from "../storage/scanStore.js";

const STATIC_DIR = fileURLToPath(new URL("./static/", import.meta.url));

export function createUiApp(): Express {
  const app = express();
  app.use(express.static(STATIC_DIR));

  app.get("/api/graph", (req, res) => {
    const repoPath = req.query.repoPath;
    if (typeof repoPath !== "string") {
      return res.status(400).json({ error: "repoPath query parameter is required" });
    }
    res.json(loadGraphForRepo(repoPath));
  });

  app.get("/api/scans", (req, res) => {
    const repoPath = typeof req.query.repoPath === "string" ? req.query.repoPath : undefined;
    res.json(listScans(repoPath));
  });

  app.get("/api/report", (req, res) => {
    const repoPath = req.query.repoPath;
    const format = (req.query.format as string) ?? "markdown";
    if (typeof repoPath !== "string") {
      return res.status(400).json({ error: "repoPath query parameter is required" });
    }
    if (format !== "markdown" && format !== "html" && format !== "json") {
      return res.status(400).json({ error: "format must be markdown, html, or json" });
    }
    const graph = loadGraphForRepo(repoPath);
    res.type(format === "html" ? "html" : "text/plain").send(renderReport(graph, format));
  });

  return app;
}
