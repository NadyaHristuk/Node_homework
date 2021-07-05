const should = require("should");
const ContactsServer = require("../../index");
const request = require("supertest");
const { requests } = require("sinon");
const userModel = require("../users/model.users");
const { promises: fsPromises } = require("fs");
require("dotenv").config();

describe("Acceptance tests suitcase example", () => {
  let server;

  before(async () => {
    const userServer = new ContactsServer();
    server = await userServer.startServer();
  });

  after(() => {
    server.close();
  });

  describe("GET /api/contacts", () => {
    it("should return OK", async () => {
      await request(server).get("/api/contacts").expect(200);
    });
  });

  describe("PATCH /users/avatars", () => {
    it("should return 401 error", async () => {
      await request(server)
        .patch("/api/users/avatars")
        .set("Content-Type", "application/json")
        .send({})
        .expect(401);
    });
  });

  describe("PATCH /users/avatars", () => {
    it("should return 200, body-perfect and avatarUrl", async () => {
      await request(server)
        .patch("/api/users/avatars")
        .auth(process.env.TEST_TOKEN, { type: "bearer" })
        .attach("avatar", "public/images/default-ava.png")
        .field("subscription", "pro")
        .expect(function (res) {
          res.body.avatar = "http://localhost:3000/images/1603743033077.png";
          res.body.subscription = "pro";
        });
    });
  });
});