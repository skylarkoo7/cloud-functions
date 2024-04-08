const functions = require("firebase-functions");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone'); // dependent on utc plugin
dayjs.extend(utc);
dayjs.extend(timezone);
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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
        secret: process.env.JWT_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {secure: false},
      }),
  );
  const getCurrentIST = () => {
    // TODO format must be 'YYYY-MM-DD HH:mm:ss'
    const datetime = dayjs().tz('Asia/Kolkata').format('YYYY-MM-DD HH:mm:ss');
    return datetime;
  };
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
        username : req.body.username,
        email: email,
        name: req.body.name,
        mobile: req.body.mobile,
        address: req.body.address,
        hashedPassword : hashedPassword,
        created_at : getCurrentIST(),
        updated_at: getCurrentIST(),
        status : null,
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
    console.log(snapshot);
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
      username : userData.username,
      email: userData.email,
      name: userData.name,
      mobile: userData.mobile,
      address: userData.address,
     };

    const token = jwt.sign({userId: userData.id}, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    req.session.token = token;

    // Generate update password token
    const updatePasswordToken = jwt.sign({ userId: userData.id }, process.env.JWT_SECRET, {
      expiresIn: "1h", // Set an appropriate expiration time
    });

    // Send token and update password token in response
    return res.status(200).json({ status: "Success",updatePasswordToken : updatePasswordToken , userInfo: userInfo });
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
    jwt.verify(updatePasswordToken, process.env.JWT_SECRET, async (err, decoded) => {
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
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
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

  const getUserIdFromToken = (token) => {
    try {
      // Verify the token
      const decoded = jwt.verify(token, process.env.JWT_SECRET); // Replace 'your_secret_key' with your actual secret key
      // Extract user ID from the decoded token
      const userId = decoded.userId;
      return userId;
    } catch (error) {
      // If token verification fails or token is invalid, return null
      return null;
    }
  };
  // Update user details based on token
app.put("/api/update-info", async (req, res) => {
  try {
    const token = req.body.token;

    // Verify the token and extract user ID
    const userId = getUserIdFromToken(token);
    console.log(userId);
    if (!userId) {
      return res.status(401).json({ status: "Failed", msg: "Invalid token" });
    }

    // Check if the user exists
    const userRef = db.collection("userDetails").doc(userId.toString());
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ status: "Failed", msg: "User not found" });
    }

    // Update user details
    await userRef.update({
      username : req.body.username,
      name: req.body.name,
      mobile: req.body.mobile,
      address: req.body.address,
      updated_at: getCurrentIST(),
    });

    return res.status(200).json({ status: "Success", msg: "Data Updated" });
  } catch (error) {
    console.error("Error updating user data:", error);
    return res.status(500).json({ status: "Failed", msg: "Internal server error" });
  }
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

// Function to send email for password reset
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
     user: 'fpfransiscopatel@gmail.com',
     pass: 'ggnn ioyf qntx jrui'
  }
 });

 const generateResetToken = () => {
  return crypto.randomBytes(20).toString('hex');
 };

 const sendResetPasswordEmail = async (email, token) => {
  const mailOptions = {
     from: 'fpfransiscopatel@gmail.com',
     to: email,
     subject: 'Password Reset',
     text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
     Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:\n\n
     Use this token ${token}\n\n
     If you did not request this, please ignore this email and your password will remain unchanged.\n`
  };
  await transporter.sendMail(mailOptions);
};

// Reset Password API Endpoint
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
 
  try {
     // Check if the user exists
     const userRef = db.collection("userDetails").where("email", "==", email);
     const snapshot = await userRef.get();
 
     if (snapshot.empty) {
       return res.status(404).json({ status: "Failed", msg: "User not found" });
     }
 
     let userData;
     snapshot.forEach((doc) => {
       userData = doc.data();
     });
 
     // Generate a reset token
     const resetToken = generateResetToken();
 
     // Save the reset token in the user's document
     await db.collection("userDetails").doc(userData.id.toString()).update({ resetToken: resetToken });
 
     // Send the reset password email
     await sendResetPasswordEmail(email, resetToken);
 
     return res.status(200).json({ status: "Success", msg: "Reset password email sent" });
  } catch (error) {
     console.error("Error resetting password:", error);
     return res.status(500).json({ status: "Failed", msg: "Internal server error" });
  }
 });
 
 // Reset password form API
 app.post('/api/reset-password-form', async (req, res) => {
  const { token, newPassword } = req.body;
 
  try {
     // Find the user with the provided token
     const userRef = db.collection("userDetails").where("resetToken", "==", token);
     const snapshot = await userRef.get();
 
     if (snapshot.empty) {
       return res.status(404).json({ status: "Failed", msg: "Invalid or expired reset token" });
     }
 
     let userData;
     snapshot.forEach((doc) => {
       userData = doc.data();
     });
 
     // Hash the new password
     const hashedPassword = await bcrypt.hash(newPassword, 10);
 
     // Update the user's password and remove the reset token
     await db.collection("userDetails").doc(userData.id.toString()).update({
       hashedPassword: hashedPassword,
       resetToken: null
     });
 
     return res.status(200).json({ status: "Success", msg: "Password reset successfully" });
  } catch (error) {
     console.error("Error resetting password:", error);
     return res.status(500).json({ status: "Failed", msg: "Internal server error" });
  }
 });


  // exports the api to firebase cloud functions
  exports.app= functions.https.onRequest(app);