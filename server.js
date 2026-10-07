import net from "net";

const PORT = process.env.PORT || 443;

const TARGET_HOST =
  process.env.TARGET_HOST || "";

const TARGET_PORT =
  Number(process.env.TARGET_PORT || 443);


console.log("=================================");
console.log("Trendify Nexus TCP Relay");
console.log("PORT:", PORT);
console.log("TARGET:", TARGET_HOST, TARGET_PORT);
console.log("=================================");


const server = net.createServer((client) => {

  console.log(
    "NEW CLIENT",
    client.remoteAddress,
    client.remotePort
  );


  if (!TARGET_HOST) {

    console.log(
      "TARGET_HOST missing"
    );

    client.destroy();

    return;
  }


  const remote = net.connect(
    {
      host: TARGET_HOST,
      port: TARGET_PORT
    },
    () => {

      console.log(
        "CONNECTED TARGET",
        TARGET_HOST,
        TARGET_PORT
      );

    }
  );


  client.pipe(remote);
  remote.pipe(client);



  client.on(
    "error",
    (err)=>{
      console.log(
        "CLIENT ERROR",
        err.message
      );
      remote.destroy();
    }
  );


  remote.on(
    "error",
    (err)=>{
      console.log(
        "REMOTE ERROR",
        err.message
      );
      client.destroy();
    }
  );


  client.on(
    "close",
    ()=>{
      remote.destroy();
    }
  );


  remote.on(
    "close",
    ()=>{
      client.destroy();
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