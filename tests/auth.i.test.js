//Server
const ContactsServer = require('../server/app');
//Packages
const request = require('supertest');
const should = require('should');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
//Models
const userModel = require('../api/users/user.model');

describe('Acceptance tests for auth api', () => {
	let server;

	before(async () => {
		const contactsServer = new ContactsServer();
		server = await contactsServer.start();
	});

	after(() => {
		server.close();
	});

	describe('POST /api/auth/register', () => {
		it('should return 400 Bad Request', async () => {
			await request(server)
				.post('/api/auth/register')
				.set('Content-Type', 'application/json')
				.send({})
				.expect(400);
		});

		context('when user with such email exists', () => {
			const existingEmail = 'example@gmail.com';
			let newUser;

			before(async () => {
				newUser = await userModel.create({ email: existingEmail, password: 'password_hash' });
			});

			after(async () => {
				await userModel.findByIdAndDelete(newUser._id);
			});

			it('should return 409 Conflict', async () => {
				await request(server)
					.post('/api/auth/register')
					.set('Content-Type', 'application/json')
					.send({ email: existingEmail, password: 'some_password' })
					.expect(409);
			});
		});

		context('when user with such email does not exist', () => {
			let newUser;

			before(async () => {});

			after(async () => {
				await userModel.findOneAndDelete({ email: newUser.body.user.email });
			});

			it('should return 201 Created', async () => {
				newUser = await request(server)
					.post('/api/auth/register')
					.set('Content-Type', 'application/json')
					.send({ email: 'new_email@gmail.com', password: 'some_password' })
					.expect(201);

				const responseBody = newUser.body;
				const createdUser = responseBody.should.have.property('user').which.is.a.Object();

				createdUser.obj.should.have.property('email').which.is.a.String();
				createdUser.obj.should.have.property('subscription').which.is.a.String();
				createdUser.obj.should.have.property('avatarURL').which.is.a.String();
				createdUser.obj.should.not.have.property('password');

				const existedUser = await userModel.findOne({ email: responseBody.user.email });

				should.exist(existedUser);
			});
		});
	});

	describe('POST /api/auth/login', () => {
		it('should return 400 Bad Request', async () => {
			await request(server)
				.post('/api/auth/login')
				.set('Content-Type', 'application/json')
				.send({})
				.expect(400);
		});

		context('when user password is invalid', async () => {
			const existingEmail = 'example1@gmail.com';
			const existingPass = 'password_hash';

			let existingUser;

			before(async () => {
				existingUser = await userModel.create({ email: existingEmail, password: existingPass });
			});

			after(async () => {
				await userModel.findByIdAndDelete(existingUser._id);
			});

			it('should return 401 Unauthorized', async () => {
				await request(server)
					.post('/api/auth/login')
					.set('Content-Type', 'application/json')
					.send({ email: existingEmail, password: 'incorrect_password' })
					.expect(401);
			});
		});

		context('when user password is valid', async () => {
			const existingEmail = 'example@gmail.com';
			const tmpPass = 'password_hash';

			let newUser;

			before(async () => {
				const encryptedPassword = await bcrypt.hash(tmpPass, 10);
				newUser = await userModel.create({ email: existingEmail, password: encryptedPassword });
			});

			after(async () => {
				await userModel.findByIdAndDelete(newUser._id);
			});

			it('should return 200 OK', async () => {
				const response = await request(server)
					.post('/api/auth/login')
					.set('Content-Type', 'application/json')
					.send({ email: existingEmail, password: tmpPass })
					.expect('Content-Type', /json/)
					.expect(200);

				const responseBody = response.body;

				responseBody.should.have.property('token').which.is.a.String();

				const createdUser = responseBody.should.have.property('user').which.is.a.Object();

				createdUser.obj.should.have.property('email').which.is.a.String();
				createdUser.obj.should.have.property('subscription').which.is.a.String();
				createdUser.obj.should.not.have.property('password');

				const existedUser = await userModel.findOne({ email: responseBody.user.email });

				should.exist(existedUser);
			});
		});
	});

	describe('POST /api/auth/logout', () => {
		const existingEmail = 'example@gmail.com';
		let newUser;

		before(async () => {
			newUser = await userModel.create({ email: existingEmail, password: 'password_hash' });

			const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY);
			const userId = await jwt.verify(token, process.env.JWT_SECRET_KEY).userId;

			newUser = await userModel.findByIdAndUpdate(userId, { token }, { new: true });
		});

		after(async () => {
			await userModel.findByIdAndDelete(newUser._id);
		});

		it('should return 401 Unauthorized', async () => {
			await request(server)
				.post('/api/auth/logout')
				.set('Authorization', `Bearer ${newUser.token}p`)
				.expect(401, { message: 'Not authorized' });
		});

		it('should return 204 Unauthorized', async () => {
			await request(server)
				.post('/api/auth/logout')
				.set('Authorization', `Bearer ${newUser.token}`)
				.expect(204);
		});
	});
});