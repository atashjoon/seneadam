import net from "net";

const PORT = Number(process.env.PORT || 443);

console.log("=================================");
console.log("Trendify Nexus Dynamic TCP Relay");
console.log("PORT:", PORT);
console.log("MODE: DYNAMIC");
console.log("=================================");


const server = net.createServer((client) => {

  console.log(
    "CLIENT CONNECTED",
    client.remoteAddress,
    client.remotePort
  );


  let header = Buffer.alloc(0);
  let connected = false;
  let remote = null;


  function connectTarget(host, port, firstData) {

    console.log(
      "CONNECT TARGET",
      host,
      port
    );


    remote = net.connect(
      {
        host,
        port
      },
      () => {

        console.log(
          "TARGET CONNECTED",
          host,
          port
        );

        connected = true;


        if (firstData.length) {
          remote.write(firstData);
        }


        client.pipe(remote);
        remote.pipe(client);

      }
    );


    remote.on(
      "error",
      err => {

        console.log(
          "REMOTE ERROR",
          err.message
        );

        client.destroy();

      }
    );


    remote.on(
      "close",
      ()=>{

        client.destroy();

      }
    );

  }



  client.once(
    "data",
    data => {


      /*
        Header format:

        HOST_LENGTH(2 bytes)
        HOST
        PORT(2 bytes)
        DATA
      */


      try {


        const hostLength =
          data.readUInt16BE(0);


        const host =
          data
          .slice(
            2,
            2 + hostLength
          )
          .toString();


        const port =
          data.readUInt16BE(
            2 + hostLength
          );


        const payload =
          data.slice(
            4 + hostLength
          );


        connectTarget(
          host,
          port,
          payload
        );


      }
      catch(err){


        console.log(
          "HEADER ERROR",
          err.message
        );


        client.destroy();


      }


    }
  );



  client.on(
    "error",
    err=>{

      console.log(
        "CLIENT ERROR",
        err.message
      );


      remote?.destroy();

    }
  );


  client.on(
    "close",
    ()=>{

      remote?.destroy();

    }
  );


});


server.listen(
  PORT,
  "0.0.0.0",
  ()=>{

    console.log(
      "Relay listening on",
      PORT
    );

  }
);
