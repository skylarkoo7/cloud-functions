const functions = require("firebase-functions");

const admin = require("firebase-admin");

const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const express = require("express");
const cors = require("cors");

// Main App is created here
const app = express();
app.use(cors({origin: true}));

// Main database reference

const db = admin.firestore();

// Routes
app.get("/", (req, res) =>{
  return res.status(200).send("How are you doing");
});

// Create -> post()
app.post("/api/create", (req, res) =>{
  (async () =>{
    try {
      await db.collection("userDetails").doc(`/${Date.now()}/`)
          .create({id: Date.now(), name: req.body.name,
            mobile: req.body.mobile, address: req.body.address});
      return res.status(200).send({status: "Success", msg: "Data Saved"});
    } catch (error) {
      return res.status(500).send({status: "Failed", msg: error});
    }
  })();
});

// Get -> get()
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
