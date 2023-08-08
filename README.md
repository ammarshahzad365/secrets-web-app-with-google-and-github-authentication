# Web Application: Secrets
**A simple anonymous secret sharing app designed with node.js and MongoDB. **

For user security, users can login either through username and password where passwords go through hashing and salting before they are saved into our database.
Along with that, users also have the option to sign up or sign in using Google and Github Authentication in which case, only their recieved ID/profile from Github or Google 
is stored in the database instead of their passwords.

MongoDB is used with Mongoose to store hashed and salted passwords as well as one secret from every user.

Passport.js is used for user authentication with Google and Github.

Node.js is used primarily to design the backend part of this application along with express and ejs (for rendering).
