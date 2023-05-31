const router = require("express").Router();
const {
  usernameVarmi,
  rolAdiGecerlimi,
  checkPayload,
} = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const bcrypt = require("bcryptjs");
const usersModel = require("../users/users-model");
const jwt = require("jsonwebtoken");

router.post(
  "/register",
  checkPayload,
  usernameVarmi,
  rolAdiGecerlimi,
  async (req, res, next) => {
    /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    try {
      let { username, password, role_name } = req.body;
      const hashedPassword = bcrypt.hashSync(password);
      let newUser = {
        username: username,
        password: hashedPassword,
        role_name: role_name,
      };
      const insertedUser = await usersModel.ekle(newUser);
      res.status(201).json(insertedUser);
    } catch (error) {
      next(error);
    }
  }
);

router.post("/login", checkPayload, usernameVarmi, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */

  try {
    let { password } = req.body;
    const isPasswordMatch = bcrypt.compareSync(
      password,
      req.currentUser.password
    );
    const payload = {
      subject: req.currentUser.user_id,
      username: req.currentUser.username,
      role_name: req.currentUser.role_name,
    };

    if (isPasswordMatch) {
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });

      res.status(200).json({
        message: `${req.currentUser.username} geri geldi!`,
        token: token,
      });
    } else {
      next(error);
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
