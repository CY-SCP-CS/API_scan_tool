// Deliberately vulnerable local demo. Never deploy this code.
const http = require("http");
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "public");

http.createServer((request, response) => {
  const url = new URL(request.url, "http://127.0.0.1:9102");
  if (url.pathname !== "/file") { response.writeHead(404); return response.end(); }
  const name = url.searchParams.get("name") || "safe.txt";
  // Intentional path traversal for scanner demonstration.
  const content = fs.readFileSync(path.join(root, name), "utf8");
  response.writeHead(200, {"content-type": "text/plain"}); response.end(content);
}).listen(9102, "127.0.0.1");
