import { makeExecutableSchema } from 'graphql-tools';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

// Construct a schema, using GraphQL schema language
const typeDefs = `
  type Query {
    currentUser: User
    hello: String
  }

  type User {
    _id: String
    email: String
    jwt: String
  }

  type Mutation {
    login(email: String!, password: String!): User
    signup(email: String!, password: String!): User
  }
`;

// Provide resolver functions for your schema fields
const resolvers = {
  Query: {
    currentUser: (root, args, context) => {
      return context.user
    },

    hello: (root, args, context) => {
      return 'Hello debuger!'
    }
  },
  Mutation: {
    signup: async (root, { email, password }, { mongo, secrets }) => {
      const Users = mongo.collection('users');
      const existingUser = await Users.findOne({ email });
      if (existingUser) {
        throw new Error('Email already used');
      }
      // 安装不了bcrypt,之后试试其他包,后来又可以安装了
      const hash = await bcrypt.hash(password, 10)
      await Users.insert({
        email,
        password: hash,
      })
      const user = await Users.findOne({ email })
      // Generate the jwt and add it to the user document being returned.
      user.jwt = jwt.sign({ _id: user._id }, secrets.JWT_SECRET);
      return user
    },
    login: async (root, { email, password }, { mongo, secrets }) => {
      const Users = mongo.collection('users')
      // Check if a user with that email address exists
      const user = await Users.findOne({ email })
      if (!user) {
        throw new Error('Email not found')
      }
      // Compare the password supplied and the password we have stored
      if (password !== user.password) {
        throw new Error('Password is incorrect')
      }
      // Generate the jwt and add it to the user document being returned.
      user.jwt = jwt.sign({ _id: user._id }, secrets.JWT_SECRET);
      return user
    }
  }
};

// Required: Export the GraphQL.js schema object as "schema"
export const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

// Optional: Export a function to get context from the request. It accepts two
// parameters - headers (lowercased http headers) and secrets (secrets defined
// in secrets section). It must return an object (or a promise resolving to it).
let mongo;
let client;
export async function context(headers, secrets) {
  if (!mongo) {
    client = await MongoClient.connect(secrets.MONGO_URL)
    mongo = client.db('learn-graphql-authentication-from-spencer')
  }
  console.log(client)
  const user = await getUser(headers['authorization'], secrets, mongo);

  return {
    headers,
    secrets,
    mongo,
    user,
  };
};

const getUser = async (authorization, secrets, mongo) => {
  const bearerLength = "Bearer ".length;
  if (authorization && authorization.length > bearerLength) {
    const token = authorization.slice(bearerLength);
    const { ok, result } = await new Promise(resolve =>
      jwt.verify(token, secrets.JWT_SECRET, (err, result) => {
        if (err) {
          resolve({
            ok: false,
            result: err
          });
        } else {
          resolve({
            ok: true,
            result
          });
        }
      })
    );

    if (ok) {
      const user = await mongo.collection('users').findOne({ _id: ObjectId(result._id) });
      return user;
    } else {
      console.error(result);
      return null;
    }
  }

  return null;
};
