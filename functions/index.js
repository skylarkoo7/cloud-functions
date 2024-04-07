const {doc, getDoc } = require("firebase/firestore");


const functions = require("firebase-functions");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");


  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  const express = require("express");
  const session = require("express-session");
  const jwt = require("jsonwebtoken");
  const cors = require("cors");
  const bcrypt = require("bcrypt");
  const app = express();
  app.use(cors({origin: true}));
  // Main database reference
  const db = admin.firestore();

  app.use(express.json());
  app.use(
      session({
        secret: "xinasdlkmasd",
        resave: false,
        saveUninitialized: true,
        cookie: {secure: false},
      }),
  );

  // Routes
  app.get("/", (req, res) =>{
    return res.status(200).send("How are you doing");
  });

  // Create -> post()
  app.post("/api/register", async (req, res) => {
    try {
      const {email, password, confirmPassword} = req.body;

      // Check if mobile number already exists
      const existingMobile = await db.collection("userDetails")
          .where("mobile", "==", req.body.mobile).get();

      if (!existingMobile.empty) {
        return res.status(400).send({
          status: "Failed",
          msg: "Mobile number already exists",
        });
      }

      // Check if email already exists
      const existingEmail = await db.collection("userDetails")
          .where("email", "==", email).get();

      if (!existingEmail.empty) {
        return res.status(400).send({
          status: "Failed",
          msg: "Email already exists",
        });
      }

      // Password length validation
      if (password.length < 6) {
        return res.status(400).send({
          status: "Failed",
          msg: "Password length should be at least 6 characters",
        });
      }

      // Confirm password validation
      if (password !== confirmPassword) {
        return res.status(400).send({
          status: "Failed",
          msg: "Passwords do not match",
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      await db.collection("userDetails").doc(`/${Date.now()}/`).create({
        id: Date.now(),
        email: email,
        name: req.body.name,
        mobile: req.body.mobile,
        address: req.body.address,
      });

      return res.status(200).send({
        status: "Success",
        msg: "Data Saved",
      });
    } catch (error) {
      console.error(error);
      return res.status(500).send({
        status: "Failed",
        msg: error,
      });
    }
  });

  // Login Facility
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try { 
    const userRef = db.collection("userDetails").where("email", "==", email);
    const snapshot = await userRef.get();

    if (snapshot.empty) {
      return res.status(401).json({ status: "Failed", msg: "Wrong credentials" });
    }

    let userData;
    snapshot.forEach((doc) => {
      userData = doc.data();
    });

    const match = await bcrypt.compare(password, userData.hashedPassword);
    if (!match) {
      return res.status(401).json({ status: "Failed", msg: "Wrong credentials" });
    }

    const userInfo = {
      id: userData.id,
      email: userData.email,
      name: userData.name,
      mobile: userData.mobile,
      address: userData.address,
     };

    const token = jwt.sign({userId: userData.id}, "xinasdlkmasd", {
      expiresIn: "1h",
    });

    req.session.token = token;

    // Generate update password token
    const updatePasswordToken = jwt.sign({ userId: userData.id }, "xinasdlkmasd", {
      expiresIn: "1h", // Set an appropriate expiration time
    });

    // Send token and update password token in response
    return res.status(200).json({ status: "Success",updatePasswordToken : updatePasswordToken , token: token, userInfo: userInfo });
  } catch (error) {
    console.error("Error fetching user:", error);
    return res.status(500).json({ status: "Failed", msg: "Internal server error" });
  }
});

// Update Password Currently in progress.
// Update Password API Endpoint
app.post("/api/update-password", async (req, res) => {
  const { updatePasswordToken, newPassword } = req.body;

  try {
    // Verify update password token
    jwt.verify(updatePasswordToken, "xinasdlkmasd", async (err, decoded) => {
      if (err) {
        return res.status(401).json({ status: "Failed", msg: "Invalid or expired update password token" });
      }

      // Get user ID from the decoded token
      const userId = decoded.userId;

      // Update user's password
      const userRef = db.collection("userDetails").doc(userId.toString());
      const userDoc = await userRef.get();

      if (!userDoc.exists) {
        return res.status(404).json({ status: "Failed", msg: "User not found" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await userRef.update({ hashedPassword: hashedPassword });

      return res.status(200).json({ status: "Success", msg: "Password updated successfully" });
    });
  } catch (error) {
    console.error("Error updating password:", error);
    return res.status(500).json({ status: "Failed", msg: "Internal server error", error: error.message });
  }
});


//Get User Info
app.get("/api/user-info", async (req, res) => {
  try {
    // Extract the token from the request header
    const token = req.headers.authorization.split(' ')[[1]];
    console.log(token);

    if (!token) {
      return res.status(401).json({ status: "Failed", msg: "No token provided" });
    }

    // Verify the token
    jwt.verify(token, "xinasdlkmasd", async (err, decoded) => {
      if (err) {
        return res.status(401).json({ status: "Failed", msg: "Invalid or expired token" });
      }

      // Get user ID from the decoded token and check its validity
      const userId = decoded.userId;
      if (typeof userId !== 'number' || userId <= 0) {
        return res.status(400).json({ status: "Failed", msg: "Invalid user ID" });
      }

      // Fetch user information from the database
      const userRef = db.collection("userDetails").doc(userId.toString());
      const userDoc = await userRef.get();

      if (!userDoc.exists) {
        return res.status(404).json({ status: "Failed", msg: "User not found" });
      }

      const userInfo = userDoc.data();

      // Return user information
      return res.status(200).json({ status: "Success", userInfo: userInfo });
    });
  } catch (error) {
    console.error("Error fetching user info:", error);
    return res.status(500).json({ status: "Failed", msg: "Internal Server Error" });
  }
});

  // Logout
  app.post("/api/logout", (req, res) => {
    try {
      // Clear session data
      req.session.destroy((err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ status: "Failed", msg: "Internal Server Error" });
        }
        res.status(200).json({ status: "Success", msg: "Logged out successfully" });
      });
    } catch (error) {
      console.error("Error during logout:", error);
      return res.status(500).json({ status: "Failed", msg: "Internal Server Error" });
    }
  });

  // Get -> get() // Checking token and providing info here
  // TODO
  app.get("/api/get/:id", (req, res) => {
    (async () => {
      try {
        const reqDoc = db.collection("userDetails").doc(req.params.id);
        const userDetail = await reqDoc.get();
        const response = userDetail.data();
        return res.status(200).send({status: "Success", data: response});
      } catch (error) {
        console.log(error);
        res.status(500).send({status: "Failed", msg: error});
      }
    })();
  });

  // read all user details
  app.get("/api/userDetails", (req, res) => {
    (async () => {
      try {
        const query = db.collection("userDetails");
        const response = [];

        await query.get().then((data) => {
          const docs = data.docs; // query results

          docs.map((doc) => {
            const selectedData = {
              name: doc.data().name,
              email: doc.data().email,
              mobile: doc.data().mobile,
              address: doc.data().address,
            };

            response.push(selectedData);
          });
          return response;
        });

        return res.status(200).send({status: "Success", data: response});
      } catch (error) {
        console.log(error);
        res.status(500).send({status: "Failed", msg: error});
      }
    })();
  });

  // Update -> put()
  app.put("/api/update/:id", (req, res) => {
    (async () => {
      try {
        const reqDoc = db.collection("userDetails").doc(req.params.id);
        await reqDoc.update({
          name: req.body.name,
          email: req.body.email,
          mobile: req.body.mobile,
          address: req.body.address,
        });
        return res.status(200).send({status: "Success", msg: "Data Updated"});
      } catch (error) {
        console.log(error);
        res.status(500).send({status: "Failed", msg: error});
      }
    })();
  });

  // Delete -> delete()
  app.delete("/api/delete/:id", (req, res) => {
    (async () => {
      try {
        const reqDoc = db.collection("userDetails").doc(req.params.id);
        await reqDoc.delete();
        return res.status(200).send({status: "Success", msg: "Data Removed"});
      } catch (error) {
        console.log(error);
        res.status(500).send({status: "Failed", msg: error});
      }
    })();
  });

  // exports the api to firebase cloud functions
  exports.app= functions.https.onRequest(app);