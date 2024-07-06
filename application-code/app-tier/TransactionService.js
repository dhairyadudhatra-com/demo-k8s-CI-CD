const dbcreds = require('./DbConfig');
const mysql = require('mysql2');

const con = mysql.createConnection({
    host: dbcreds.DB_HOST,
    user: dbcreds.DB_USER,
    password: dbcreds.DB_PWD,
    database: dbcreds.DB_DATABASE,
    port: dbcreds.DB_PORT
});

function createTransactionsTable() {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        amount DECIMAL(10, 2) NOT NULL,
        description VARCHAR(255) NOT NULL
      )
    `;
      
    con.query(createTableSQL, function (err, result) {
      if (err) {
        console.error('Error creating transactions table:', err);
      } else {
        console.log('Transactions table created or already exists.');
      }
    });
}

async function addTransaction(amount, desc) {
    try {
      // Execute the query asynchronously
      const sql = `INSERT INTO transactions (amount, description) VALUES (?, ?)`;
      const result = await con.promise().query(sql, [amount, desc]);
      console.log(`Transactions of amount ${amount} added with desc ${desc} ...`);
      return 200; // Success status code
    } catch (error) {
      return 400; // Error status code
    }
  }

async function getAllTransactions(callback){
  
    const mysql = "SELECT * FROM transactions";
    con.query(mysql, function(err, result){
        if (err) {
            console.error("Error fetching transactions:", err);
            return callback(err, null); // Pass the error to the callback
        }
        console.log("Getting all transactions...");
        return callback(null, result); // Pass the result to the callback
    });
}

function findTransactionById(id,callback){
    var mysql = `SELECT * FROM transactions WHERE id = ${id}`;
    con.query(mysql, function(err,result){
        if (err && result.length<1) {
            console.error("Error fetching transactions of given ID:", err);
            return callback(result); // Pass the error to the callback
        }
        console.log(`retrieving transactions with id ${id}`);
        return(callback(result));
    }) 
}

function deleteAllTransactions(callback){
    var mysql = "DELETE FROM transactions";
    con.query(mysql, function(err,result){
        if (err) throw err;
        console.log("Deleting all transactions...");
        return(callback(result));
    }) 
}

function deleteTransactionById(id, callback){
    var mysql = `DELETE FROM transactions WHERE id = ${id}`;
    con.query(mysql, function(err,result){
        if (err) throw err;
        console.log(`Deleting transactions with id ${id}`);
        return(callback(result));
    }) 
}


module.exports = {createTransactionsTable, addTransaction ,getAllTransactions, deleteAllTransactions, deleteAllTransactions, findTransactionById, deleteTransactionById};







