//mongodb

require("./config/db");

const app = require("express")();
const port = process.env.PORT || 3000;
const UserRouter = require("./api/User");

//cors
const cors = require("cors");
app.use(cors());

//for accepting post from data
const bodyParser = require("express").json;
app.use(bodyParser());

app.use("/user", UserRouter);

app.listen(port, () => {
  console.log(`server running on port ${port}`);
});
