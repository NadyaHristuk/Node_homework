//Server
const ContactsServer = require('../server/app');
//Packages
const request = require('supertest');
const should = require('should');
const jwt = require('jsonwebtoken');
//Models
const userModel = require('../api/users/user.model');

describe('Acceptance tests for user api', () => {
	let server;
	let newUser;

	const someEmail = 'example@gmail.com';
	const somePassword = 'password_hash';
	const someAvatarUrl = 'http://localhost:3001/tmp/1612718733366.png';

	before(async () => {
		const contactsServer = new ContactsServer();
		server = await contactsServer.start();

		newUser = await userModel.create({
			email: someEmail,
			password: somePassword,
			avatarURL: someAvatarUrl,
		});

		const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET_KEY);
		const userId = await jwt.verify(token, process.env.JWT_SECRET_KEY).userId;

		newUser = await userModel.findByIdAndUpdate(userId, { token }, { new: true });
	});

	after(async () => {
		await userModel.findOneAndDelete({ email: newUser.email });

		server.close();
	});

	describe('GET /api/users/current', () => {
		it('should return 401 Unauthorized', async () => {
			await request(server)
				.get('/api/users/current')
				.set('Authorization', `Bearer ${newUser.token}p`)
				.expect('Content-Type', /json/)
				.expect(401, { message: 'Not authorized' });
		});

		it('should return 200 OK', async () => {
			const currentUser = await request(server)
				.get('/api/users/current')
				.set('Authorization', `Bearer ${newUser.token}`)
				.expect('Content-Type', /json/)
				.expect(200);

			const response = currentUser.body;

			response.should.have.property('email').which.is.a.String();
			response.should.have.property('subscription').which.is.a.String();
			response.should.not.have.property('password');

			const existedUser = await userModel.findOne({ email: response.email });
			should.exist(existedUser);
		});
	});

	describe('PATCH /api/users/avatars', () => {
		it('should return 401 Unauthorized', async () => {
			await request(server)
				.patch('/api/users/avatars')
				.set('Authorization', `Bearer ${newUser.token}p`)
				.attach('avatar', 'temp/1612718734058.png')
				.field('avatarURL', 'http://localhost:3001/images/1612718734058.png')
				.expect('Content-Type', /json/)
				.expect(401, { message: 'Not authorized' });
		});

		it('should return 200 OK', async () => {
			const updatedUser = await request(server)
				.patch('/api/users/avatars')
				.set('Authorization', `Bearer ${newUser.token}`)
				.attach('avatar', 'temp/1612718734058.png')
				.field('avatarURL', 'http://localhost:3001/images/1612718734058.png')
				.expect('Content-Type', /json/)
				.expect(200);

			const response = updatedUser.body;
			response.should.have.property('avatarURL').which.is.a.String();
			response.should.not.have.property('password');

			const existedUser = await userModel.findOne({ email: someEmail });

			should.exists(existedUser.avatarURL);
		});
	});
});