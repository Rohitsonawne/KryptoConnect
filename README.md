# KryptoConnect

Simple chat server using Express and Socket.IO.

## Deploying

This project can be deployed to platforms like Render or Heroku.

Heroku / Render quick steps:

1. Ensure `package.json` has a `start` script (it does: `node server.js`).
2. Create a Git repo, commit changes, and push to your remote.
3. On Heroku: `heroku create` then `git push heroku main`.
4. On Render: Create a new Web Service, connect your repo, and set the build command to `npm install` and start command to `npm start` or leave default to use `Procfile`.

Environment:
- The server reads `process.env.PORT` for the port (default 3000 locally).

Notes & Next steps:
- Replace in-memory storage with a real database for production.
- Hash passwords before storing and use HTTPS.
- Add logging and environment-based configuration.
