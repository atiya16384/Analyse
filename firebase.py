// Import the required Firebase modules
import { initializeApp } from "firebase/app";
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut } from "firebase/auth";
import { getFirestore, collection, addDoc, getDocs, query, where, updateDoc, doc } from "firebase/firestore";
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";

// Firebase configuration object (replace with your Firebase project's details)
const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_AUTH_DOMAIN",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_STORAGE_BUCKET",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
const auth = getAuth(firebaseApp);

// Initialize Firestore
const db = getFirestore(firebaseApp);

// Initialize Firebase Storage
const storage = getStorage(firebaseApp);

// Export Firebase services for use in other files
export {
    auth,
    db,
    storage,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    signOut,
    collection,
    addDoc,
    getDocs,
    query,
    where,
    updateDoc,
    doc,
    ref,
    uploadBytes,
    getDownloadURL
};

// Example function: Sign up a new user
export const signUpUser = async (email, password) => {
    try {
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        console.log("User signed up:", userCredential.user);
    } catch (error) {
        console.error("Error signing up:", error.message);
    }
};

# Example function: Sign in a user
export const signInUser = async (email, password) => {
    try {
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        console.log("User signed in:", userCredential.user);
    } catch (error) {
        console.error("Error signing in:", error.message);
    }
};

#  Example function: Log out a user
export const logoutUser = async () => {
    try {
        await signOut(auth);
        console.log("User signed out successfully.");
    } catch (error) {
        console.error("Error logging out:", error.message);
    }
};

#  Example function: Add a document to Firestore
export const addDocument = async (collectionName, data) => {
    try {
        const docRef = await addDoc(collection(db, collectionName), data);
        console.log("Document written with ID:", docRef.id);
    } catch (error) {
        console.error("Error adding document:", error.message);
    }
};

# Example function: Get documents from Firestore
export const getDocuments = async (collectionName, field, value) => {
    try {
        const q = query(collection(db, collectionName), where(field, "==", value));
        const querySnapshot = await getDocs(q);
        querySnapshot.forEach(doc => {
            console.log(`${doc.id} =>`, doc.data());
        });
    } catch (error) {
        console.error("Error getting documents:", error.message);
    }
};

#  Example function: Upload a file to Firebase Storage
export const uploadFile = async (filePath, file) => {
    try {
        const storageRef = ref(storage, filePath);
        const snapshot = await uploadBytes(storageRef, file);
        const downloadURL = await getDownloadURL(snapshot.ref);
        console.log("File available at:", downloadURL);
        return downloadURL;
    } catch (error) {
        console.error("Error uploading file:", error.message);
    }
};
