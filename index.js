import express from "express";
import Datastore from "nedb-promise";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import { ensureAuthentication } from "./midleware/authentication.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize the database correctly
let users = new Datastore({ filename: "users.db", autoload: true });

// middleware

app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

// User auth api endpoints

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(422).json({ message: "Provide all fields" });
    }

    // check for email if exists

    if (await users.findOne({ email })) {
      return res.status(408).json({ message: "Email already exists" });
    }
    // hash the password
    const hashPassword = await bcrypt.hash(password, 10);

    const newUser = await users.insert({ name, email, password: hashPassword, role: role ?? "member" });

    return res.status(201).json({ message: "User registerd succesfully" });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

// Login user

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(422).json({ message: "Fill in all field (email and password" });
    }

    // check if user is registerd already

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    // compare the password match

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    // generate jsonwebtoken

    const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESSTOKEN_SECRET, { subject: "Access API", expiresIn: "1h" });
    // const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESHTOKEN_SECRET, { subject: user.email, expiresIn: "1d" });

    return res.status(200).json({ id: user._id, name: user.name, accessToken });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

//  Get the current user

app.get("/api/users/current", ensureAuthentication, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    return res.status(200).json({ id: user._id, name: user.name, email: user.email });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

function authorizeRole(roles = []) {
  return async (req, res, next) => {
    const user = await users.findOne({ _id: req.user.id });
    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

app.get("/api/moderator", ensureAuthentication, authorizeRole(["admin", "moderator"]), (req, res) => {
  return res.status(200).json({ message: "Admin  or Moderators only can access this route!" });
});
app.get("/api/admin", ensureAuthentication, authorizeRole(["admin"]), (req, res) => {
  return res.status(200).json({ message: "Admin only can access this route!" });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
