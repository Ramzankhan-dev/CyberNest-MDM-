const admin = require("firebase-admin");
require("dotenv").config();

// This file initializes Firebase Admin SDK so the backend can send
// push messages (policies/commands) to Android devices via FCM.
//
// Locally: reads the downloaded service account JSON file directly.
// On Render (or any host where you can't upload that file safely):
// paste the ENTIRE JSON file's content as one line into an
// environment variable called FIREBASE_SERVICE_ACCOUNT_JSON instead.

let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} else {
  serviceAccount = require("../firebase-service-account.json");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

module.exports = admin;

