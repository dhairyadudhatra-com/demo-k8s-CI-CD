const transactionService = require('./TransactionService');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const os = require('os');
const fetch = require('node-fetch');

const app = express();
const port = process.env.PORT || 4000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());

// ROUTES FOR OUR API
// =======================================================

//Liveness for k8s
app.get('/liveness',(req,res)=>{
    res.status(200).json({message:'Alive'});
});

//Readiness for k8s
app.get('/readiness', async (req, res) => {
    try {
        await transactionService.checkDatabaseConnection();
        res.status(200).send('Ready');
    } catch (err) {
        res.status(500).send('Not Ready !!');
    }
});

// ADD TRANSACTION
app.post('/transaction', (req,res)=>{
    var response = "";
    try{
        var success = transactionService.addTransaction(req.body.amount,req.body.desc);
        if (success = 200) {res.json({ message: 'added transaction successfully'});}
    }catch (err){
        res.json({ message: 'something went wrong', error : err.message});
    }
});

// GET ALL TRANSACTIONS
app.get('/transaction',(req,res)=>{
    
    transactionService.getAllTransactions(function (err, results) {
      if (err) {
        console.error("Error fetching transactions:", err);
        return res.status(500).json({ message: "Could not get all transactions", error: err.message });
      }
  
      try {
        var transactionList = results.map(row => ({
          id: row.id,
          amount: row.amount,
          description: row.description
        }));
  
        console.log("Transaction List: ", transactionList);
        res.status(200).json({ result: transactionList });
      } catch (err) {
        console.error("Error processing transactions:", err);
        res.status(500).json({ message: "Error processing transactions", error: err.message });
      }
    });
  });

//DELETE ALL TRANSACTIONS
app.delete('/transaction',(req,res)=>{
    try{
        transactionService.deleteAllTransactions(function(result){
            res.statusCode = 200;
            res.json({message:"delete function execution finished."})
        })
    }catch (err){
        res.json({message: "Deleting all transactions may have failed.", error:err.message});
    }
});

//DELETE ONE TRANSACTION
app.delete('/transaction/id', (req,res)=>{
    try{
        //probably need to do some kind of parameter checking
        transactionService.deleteTransactionById(req.body.id, function(result){
            res.statusCode = 200;
            res.json({message: `transaction with id ${req.body.id} seemingly deleted`});
        })
    } catch (err){
        res.json({message:"error deleting transaction", error: err.message});
    }
});

//GET SINGLE TRANSACTION
app.get('/transaction/id',(req,res)=>{
    //also probably do some kind of parameter checking here
    try{
        transactionService.findTransactionById(req.body.id,function(result){
            if (result && result.length > 0) {
                res.statusCode = 200;
                var id = result[0].id;
                var amt = result[0].amount;
                var desc= result[0].desc;
                res.json({"id":id,"amount":amt,"desc":desc});
            } else {
                res.json({message:`transaction with id ${req.body.id} not found`});
            }
        });

    }catch(err){
        res.json({message:"error retrieving transaction", error: err.message});
    }
});

  app.listen(port, () => {
    console.log(`AB3 backend app listening at http://localhost:${port}`)
    transactionService.createTransactionsTable();
  })
