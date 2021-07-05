const should = require("should");
const sinon = require("sinon");
const controllersUsers = require("../users/controllers.users");
const userModel = require("../users/model.users");
const jwt = require("jsonwebtoken");
require("dotenv").config();

describe("unit test", () => {
  describe("#CheckAutorizationNoToken", (noToken = "", forResSend = "Not authorized") => {
    let sandbox;
    let actualResult;
    let findByIdStub;
    let jwtStub;
    let nextStub;
    let reqStub = {
      get() {},
    };
    let resStub = {
      status() {},
      send() {},
    };
    let resStubres;

    before(async () => {
      sandbox = sinon.createSandbox();
      findByIdStub = sandbox.stub(userModel, "findById");
      jwtStub = sandbox.stub(jwt, "verify");

      sandbox.stub(reqStub, "get").returns(noToken);
      sandbox.stub(resStub, "status").returns({ send: () => forResSend });

      nextStub = sandbox.stub();

      try {
        actualResult = await controllersUsers.authorization(reqStub, resStub, nextStub);
      } catch (err) {
        actualResult = err;
      }
    });

    after(() => {
      sandbox.restore();
    });

    it("Should return result: Not authorized", () => {
      actualResult.should.be.eql("Not authorized");
    });
  });

  describe("#CheckAutorizationInvalidToken", (invalidToken = "invalid-token", forResSend = "Invalid Token") => {
    let sandbox;
    let actualResult;
    let findByIdStub;
    let jwtStub;
    let nextStub;
    let reqStub = {
      get() {},
    };
    let resStub = {
      status() {},
      send() {},
    };

    before(async () => {
      sandbox = sinon.createSandbox();
      findByIdStub = sandbox.stub(userModel, "findById");
      jwtStub = sandbox.stub(jwt, "verify");

      sandbox.stub(reqStub, "get").returns(invalidToken);
      sandbox.stub(resStub, "status").returns({ send: () => forResSend });

      nextStub = sandbox.stub();

      try {
        actualResult = await controllersUsers.authorization(reqStub, resStub, nextStub);
      } catch (err) {
        actualResult = err;
      }
    });

    after(() => {
      sandbox.restore();
    });

    it("Should return  result Invalid Token", () => {
      actualResult.should.be.eql("Invalid Token");
    });
  });

  describe("#CheckAutorizationValidToken", (_id = "5f8734258c98550ba8a10943") => {
    let sandbox;
    let actualResult;
    let findByIdStub;
    let jwtStub;
    let nextStub;
    let reqStub = {
      get() {},
    };
    let resStub = {
      status() {},
      send() {},
    };

    const tokenTime = "1h";
    const tokenTest =
      "Bearer " +
      jwt.sign({ id: _id }, process.env.TOKEN_SECRET, {
        expiresIn: tokenTime,
      });

    before(async () => {
      sandbox = sinon.createSandbox();
      findByIdStub = sandbox.stub(userModel, "findById").resolves({
        subscription: "free",
        _id,
        email: "test@gm.com",
        password: "passTest",
        __v: 0,
        token: tokenTest.slice(7),
        music: [],
        avatarURL: "http://localhost:3000/images/1603142357477.jpg",
      });
      jwtStub = sandbox.stub(jwt, "verify").resolves({ id: _id });

      sandbox.stub(reqStub, "get").returns(tokenTest);
      sandbox.stub(resStub, "status").returns({ send: () => forResSend });

      nextStub = sandbox.stub();

      try {
        actualResult = await controllersUsers.authorization(reqStub, resStub, nextStub);
      } catch (err) {
        actualResult = err;
      }
    });

    after(() => {
      sandbox.restore();
    });

    it("Should return  result Invalid Token", () => {
      sinon.assert.calledOnce(nextStub);
    });
  });
});
