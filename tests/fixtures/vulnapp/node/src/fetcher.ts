import { promises as fs } from "fs";
import * as path from "path";

import type { Request, Response } from "express";

const EXPORT_DIR = path.join(__dirname, "..", "exports");
const PARTNER_FEEDS: Record<string, string> = {
  carrier: "https://carrier.vulnapp.internal/v1/rates",
  tax: "https://tax.vulnapp.internal/v1/rates",
};

export async function proxyFeed(req: Request, res: Response): Promise<void> {
  const target = String(req.query.url);
  const upstream = await fetch(target);
  res.type("application/json").send(await upstream.text());
}

export async function partnerRates(req: Request, res: Response): Promise<void> {
  const feed = PARTNER_FEEDS[String(req.query.partner)];
  if (!feed) {
    res.status(404).end();
    return;
  }
  const upstream = await fetch(feed);
  res.type("application/json").send(await upstream.text());
}

export async function downloadExport(req: Request, res: Response): Promise<void> {
  const file = path.join(EXPORT_DIR, String(req.query.name));
  const body = await fs.readFile(file);
  res.type("text/csv").send(body);
}

export async function downloadReport(req: Request, res: Response): Promise<void> {
  const file = path.join(EXPORT_DIR, path.basename(String(req.query.name)));
  const body = await fs.readFile(file);
  res.type("text/csv").send(body);
}
