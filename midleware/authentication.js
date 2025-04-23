import jwt from "jsonwebtoken";

// midleware to check for authentication
export const ensureAuthentication = async (req, res, next) => {
  const accessToken = req.headers.authorization;
  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }
  // verify access token

  try {
    const decodeAccessToken = jwt.verify(accessToken, process.env.ACCESSTOKEN_SECRET);
    req.user = { id: decodeAccessToken.userId };
    next();
  } catch (error) {
    return res.status(401).json({ message: "Access token invalid or expired" });
  }
};
