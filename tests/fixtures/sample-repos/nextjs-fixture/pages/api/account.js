import { getServerSession } from "next-auth";

export default async function handler(req, res) {
  const session = await getServerSession(req, res);
  if (!session) return res.status(401).json({ error: "unauthorized" });
  res.json({ email: session.user.email });
}
