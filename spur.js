const Client = require('bitcoin-core');
const http = require('http');
const https = require('https');
const querystring = require('querystring');
const sqlite = require('sqlite3').verbose();
const fs = require("fs");
const async = require('async');
const crypto = require('ursa');
const timestamp = require('unix-timestamp');

const config = require('config');

const file = config.get('db_file');
const exists = fs.existsSync(file);

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

var db = new sqlite.Database(file);

var txFee = config.get('txFee');
var min_amount = config.get('min_amount');
var max_amount = config.get('max_amount');
var number_confirmations = config.get('number_confirmations');

var ready = 0;

navClient = new Client({

  username: config.get('rpc_user'),
  password: config.get('rpc_password'),
  port: config.get('rpc_port'),
  host: config.get('rpc_host'),

})

db.serialize(() =>
{

  if(!exists)
  {

    db.run("CREATE TABLE spur (date INT, src CHAR, dest CHAR, value FLOAT,amount FLOAT, fee FLOAT, flag1 FLOAT, flag2 INT, flag3 INT, flag4 CHAR, flag5 CHAR, flag6 CHAR)");

  }

});

console.log("Starting SPUR")

check();

function check()
{
  var post_data = "num_addresses=0"

  var post_options = {
      host: config.get('incoming_host'),
      port: config.get('incoming_port'),
      path: '/api/check-node',
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(post_data)
      }
  };

  var post_req = https.request(post_options,(res) =>
    {

    res.setEncoding('utf8');
    res.on('data', (chunk) =>
    {

      var json = JSON.parse(chunk);

      if(json.status == 200 && json.type == "SUCCESS")
      {

        txFee = json.data.transaction_fee;
        min_amount = json.data.min_amount;
        max_amount = json.data.max_amount;
        console.log("\nTx Fee: "+txFee+"\nMin amount: "+min_amount+"\nMax amount: "+max_amount+"\n\n")
        ready = 1;
        mainLoop();

      }
      else
      {

        setTimeout(check, 10000);

      }

    });

  });

  post_req.on('error', (err) =>
  {

    console.log("Err check(): "+err)
    setTimeout(check, 10000);

  })


  post_req.write(post_data);
  post_req.end();

}


function mainLoop()
{

  async.series([(callback) =>
    {

    db.get("SELECT COUNT(*) AS count FROM spur WHERE dest is NULL", (err,rows)=>
    {

      async.forEachLimit(Array(10 - rows.count), 1, (n, c) =>
      {

        navClient.getNewAddress().then((address) =>
        {

          console.log("Adding new Address to pool.");
          db.run("INSERT INTO spur (src) VALUES (?)", address);
          c();

        }).catch((e) =>
        {

          console.log("Fatal error: "+e);
          c();

        })

      }, (err) =>
      {

        callback();

      })

    })

  },
  (callback) =>
  {

    db.get("SELECT src FROM spur WHERE date IS NOT NULL AND date < ?", timestamp.now("-12h"), (err,rows)=>
    {

      if(err)
      {

        console.error("Err checkingexpired: "+err)

      }
      else if(rows && rows.length > 0)
      {

          db.run("DELETE FROM spur WHERE src = ?", n.src);

      }

      callback();

    });

  },
  (callback) =>
  {

    db.all("SELECT *  FROM spur WHERE (flag2 is NULL OR flag2 == 0) AND (dest IS NOT NULL)",
    (err,rows) =>
    {

      async.forEachLimit(rows, 1, (n, c) =>
      {

        navClient.getReceivedByAddress(n.src,number_confirmations)
        .then((received_amount) =>
        {

          db.run("UPDATE spur SET flag1 = ? WHERE src = ?", [received_amount,n.src]);
          if(received_amount >= n.amount)
          {

            var n_addr = 1;

            var post_data = "num_addresses="+n_addr;

            var post_options = {
                host: '176.9.19.245',
                port: '3000',
                path: '/api/check-node',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(post_data)
                }
            };

            var post_req = https.request(post_options, (res) =>
            {

              res.setEncoding('utf8');
              res.on('data', (chunk) =>
              {

                var json = JSON.parse(chunk);

                if(json.status == 200 && json.type == "SUCCESS")
                {

                  var anonAddr = json.data.nav_addresses;
                  var pubKey = json.data.public_key;

                  if(txFee !=  json.data.transaction_fee ||
                     min_amount != json.data.min_amount  ||
                     max_amount != json.data.max_amount)
                  {

                    console.log("\nTx Fee: "+txFee+"\nMin amount: "+min_amount+"\nMax amount: "+max_amount+"\n\n")

                  }

                  txFee = json.data.transaction_fee;
                  min_amount = json.data.min_amount;
                  max_amount = json.data.max_amount;

                  var pubKey = json.data.public_key;

                  var crt = crypto.createPublicKey(pubKey);
                  var msg = crt.encrypt(n.dest, 'utf8', 'base64',crypto.RSA_PKCS1_PADDING);

                  if(n_addr == anonAddr.length){

                    async.forEachLimit(anonAddr, 1, (na, cb) =>
                    {

                      navClient.sendToAddress(na, parseFloat(n.amount), null, null, msg, (tx,er) =>
                      {

                        if(err)
                        {

                          console.log("Err sendtoaddress: "+err)
                          cb();

                        }
                        else
                        {

                          db.run("UPDATE spur SET flag2 = 1, flag6 = ? WHERE src = ?",
                          tx, n.src, (er) =>
                          {

                            console.log("Err updatedbsendtoaddress: "+er)

                          })

                          cb();

                        }

                      }).catch((e) =>
                      {

                        console.log("Fatal error: "+e);
                        cb();

                      });

                    }, (err) =>
                    {

                      c();

                    })

                  }
                  else
                  {

                    console.log("Err: We've asked for "+n_addr+" addresses but got instead "+anonAddr.length);
                    c();

                  }

                }
                else
                {

                  console.log("Err: Can't connect to Incoming Server");
                  c();

                }

              });

            });

            post_req.on('error', (err) =>
            {

              console.log("Err connectingtoincoming: "+ err);
              c();

            })

            post_req.write(post_data);
            post_req.end();

          }
          else
          {

            c();

          }

        })

      }, (err) =>
      {

        callback();

      })

    })

  }], (err, results) => {

    setTimeout(() => {

      mainLoop();

    },1000)

  })


}

function handleRequest(request, response){

  var query = request.url.split("/api/");

  var parametros = querystring.parse(query[1])

  if(ready == 0)
  {

    writeServer(response,{
      err:'Service in manteinance mode.'
    });

  }
  else if(parametros.do == "newAddress")
  {

    if(parametros.address && parametros.amount)
    {

      navClient.validateAddress(parametros.address).then((result) =>
      {

        if(result.isvalid == false && result.ismine != false)
        {

          writeServer(response,{
            err:'The specified NAV Address is not valid.'
          });

        }
        else if(parseFloat(parametros.amount) < min_amount ||
              !(parseFloat(parametros.amount) > 0) ||
                parseFloat(parametros.amount) > max_amount)
        {

            writeServer(response,{
              err:'Amount should be between '+min_amount+'NAV and '+max_amount+'NAV.'
            });

        }
        else
        {

          require('crypto').randomBytes(48, (err, buffer) =>
          {

            var token = buffer.toString('hex');
            db.get("SELECT flag6 AS id, src AS addr FROM spur WHERE dest is NULL", (err,row) =>
            {

              db.run("UPDATE spur SET flag6 = ?, date = ?, fee = ?, dest = ?, value = ?, amount = ? WHERE src = ?", [
                token,
                parseInt(timestamp.now()),
                txFee,
                parametros.address,
                parseFloat(parametros.amount).toFixed(8),
                parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+(txFee/100))).toFixed(8),
                row.addr
              ], (err) =>
              {

                if(!err)
                {

                  row.fee = txFee;
                  row.id = token;
                  row.amount = parseFloat(parseFloat(parametros.amount).toFixed(8)*(1+(txFee/100))).toFixed(8);
                  row.value = parseFloat(parametros.amount).toFixed(8);
                  row.err = "";
                  writeServer(response,row);

                }
                else
                {

                  writeServer(response,{
                    err:'Please, try again later..'
                  });

                }

              });

            })

          });

        }

      }).catch((e) =>
      {

        writeServer(response,{
          err:'Please, try again later..'
        });

      })

    }
    else
    {

      writeServer(response,{
        err:'Please indicate an address and an amount.'
      });

    }

  }
  else if(parametros.do == "checkTx")
  {

    if(parametros.id)
    {

      db.get("SELECT flag6 AS id, src AS addr, fee, amount, value, date FROM spur WHERE flag6 = ?",
        parametros.id, (err,row) =>
      {

        if(err)
        {

          writeServer(response,{
            err:'Please, try again later.'
          });

        }
        else if(row)
        {

          if(parseInt(row.date) > parseInt(timestamp.now("-6h")))
          {

            row.err = "";
            row.expires = parseInt((parseInt(row.date) + (60*60*6)) - timestamp.now());
            writeServer(response,row);

          }
          else
          {

            writeServer(response,{
              err:'Expired.'
            });

          }

        }
        else
        {

          writeServer(response,{
            err:'Wrong TX id.'
          });

        }

      })

    }
    else
    {

      writeServer(response,{
        err:'Wrong TX id.'
      });

    }

  }
  else if(parametros.do == "getPubKey")
  {

    var n_addr = 0;

    var post_data = "num_addresses="+n_addr;

    var post_options = {
        host: config.get('incoming_host'),
        port: config.get('incoming_port'),
        path: '/api/check-node',
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(post_data)
        }

    };

    var post_req = https.request(post_options, (res) =>
    {

        res.setEncoding('utf8');
        res.on('data', (chunk) =>
        {

          var json = JSON.parse(chunk);

          if(json.status == 200 && json.type == "SUCCESS")
          {

            var pubKey = json.data.public_key;

            writeServer(response,{
              err:'', pubKey: pubKey
            });

          }
          else
          {

            writeServer(response,{
              err:'Can\'t connect to server, please try again later.'
            });

          }

        });

    });

    post_req.on('error', (err) =>
    {

      writeServer(response,{
        err:'Can\'t connect to server, please try again later.'
      });

    })

    post_req.write(post_data);
    post_req.end();

  }
  else if(parametros.do == "checkAddr")
  {

    if(parametros.address && parametros.id)
    {

      navClient.validateAddress(parametros.address).then((result) =>
      {

        if(result.isvalid == false || result.ismine == false)
        {

          writeServer(response,{
            err:'The specified NAV Address is not valid.'
          });

        }
        else
        {

          db.all("SELECT * FROM spur WHERE src = ? AND flag6 = ?",
          [parametros.address,parametros.id], (err,rows) =>
          {

            if(rows && rows.length > 0)
            {

              var expires = parseInt((parseInt(rows[0].date) + (60*60*6)) - timestamp.now());
              writeServer(response,{
                err:'',
                expires: expires,
                val:rows[0].amount,
                expected:rows[0].amount,
                status:rows[0].flag2?rows[0].flag2:0
              });

            }
            else
            {

              writeServer(response,{
                err:'Wrong pair Address/ID',
                val:0,
                expected:0
              });

            }

          });

        }

      }).catch((e) =>
      {

        writeServer(response,{
          err:'Please, try again later..'
        });

      });

    }
    else
    {

      writeServer(response,{
        err:'Please indicate an address.'
      });

    }

  }
  else
  {

    writeServer({
      err:'Wrong call.'
    });

  }

};

var server = http.createServer(handleRequest);

server.listen(8080);

const writeServer = (r,j) =>
{

  r.write(JSON.stringify(j));
  r.end();

}
