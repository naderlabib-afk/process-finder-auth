const fetch = require("node-fetch");

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const OWNER = process.env.GITHUB_OWNER;
const REPO = process.env.GITHUB_REPO;

async function getUsersFromGitHub() {
  try {
    const response = await fetch(
      `https://github.ibm.com/api/v3/repos/${OWNER}/${REPO}/contents/config/users.json`,
      {
        headers: {
          Authorization: `Bearer ${GITHUB_TOKEN}`,
          Accept: "application/vnd.github+json"
        }
      }
    );

    // ✅ FIX 1: Handle HTTP errors properly
    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status}`);
    }

    const data = await response.json();

    // ✅ Validate response structure
    if (!data.content) {
      throw new Error("Invalid response from GitHub (missing content)");
    }

    // ✅ Decode base64 content
    const decoded = Buffer.from(data.content, "base64").toString("utf-8");

    const parsed = JSON.parse(decoded);

    // ✅ FIX 2: Normalize structure (VERY IMPORTANT)
    // Ensures frontend always receives { users: [...] }
    return Array.isArray(parsed)
      ? { users: parsed }
      : parsed;

  } catch (error) {
    console.error("❌ GitHub fetch error:", error);
    throw error;
  }
}

module.exports = { getUsersFromGitHub };
