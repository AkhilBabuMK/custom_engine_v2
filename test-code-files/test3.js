fetch('/json?a=' + window.location.search)
  .then((res) => res.json())
  .then(data => {
    document.querySelector('h1').innerHTML = `Hello, ${data.bla}!`;
  })

testFunction = () => {
  const urlParams = new URLSearchParams(window.location.search);
  const userInput = urlParams.get("input"); // User-controlled input
  
  // Potential XSS vulnerability: inserting user input directly into the DOM
  document.getElementById("output").innerHTML = "User says: " + userInput;
};

// // testFunction();


// const express = require("express");
// const mysql = require("mysql");
// const app = express();

// const connection = mysql.createConnection({
//     host: "localhost",
//     user: "root",
//     password: "password",
//     database: "testdb"
// });

// app.get("/user", (req, res) => {
//     const userId = req.query.id; // User-controlled input
    
//     // Potential SQL Injection vulnerability
//     const query = `SELECT * FROM users WHERE id = '${userId}'`;
    
//     connection.query(query, (error, results) => {
//         if (error) {
//             res.status(500).send("Database error");
//         } else {
//             res.json(results);
//         }
//     });
// });

// app.listen(3000, () => {
//     console.log("Server running on port 3000");
// });



// document.addEventListener('DOMContentLoaded', function() {
//     const params = new URLSearchParams(window.location.search);
//     const query = params.get('q'); // User-controlled input
    
//     if (query) {
//         // Potential XSS vulnerability: directly inserting user input into innerHTML
//         document.getElementById('search-results').innerHTML = `<h1>Search Results for: ${query}</h1>`;
//     }
// });
