var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import dotenv2 from "dotenv";
import express2 from "express";

// server/routes.ts
import { createServer } from "http";

// db/index.ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";

// db/schema.ts
var schema_exports = {};
__export(schema_exports, {
  insertTransactionSchema: () => insertTransactionSchema,
  insertUserSchema: () => insertUserSchema,
  insertWalletSchema: () => insertWalletSchema,
  selectTransactionSchema: () => selectTransactionSchema,
  selectUserSchema: () => selectUserSchema,
  selectWalletSchema: () => selectWalletSchema,
  transactionStatusEnum: () => transactionStatusEnum,
  transactionTypeEnum: () => transactionTypeEnum,
  transactions: () => transactions,
  transactionsRelations: () => transactionsRelations,
  users: () => users,
  usersRelations: () => usersRelations,
  wallets: () => wallets,
  walletsRelations: () => walletsRelations
});
import { pgTable, text, serial, integer, boolean, timestamp, decimal, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { relations } from "drizzle-orm";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").unique().notNull(),
  email: text("email").unique().notNull(),
  password: text("password").notNull(),
  firstName: text("first_name"),
  lastName: text("last_name"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
  isVerified: boolean("is_verified").default(false),
  kycStatus: text("kyc_status").default("unverified"),
  isAdmin: boolean("is_admin").default(false)
});
var wallets = pgTable("wallets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  currency: text("currency").notNull(),
  // BTC, ETH, USDT, etc.
  balance: decimal("balance", { precision: 18, scale: 8 }).default("0").notNull(),
  address: text("address").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var transactionTypeEnum = pgEnum("transaction_type", [
  "deposit",
  "withdrawal",
  "transfer",
  "buy",
  "sell",
  "mining_reward"
]);
var transactionStatusEnum = pgEnum("transaction_status", [
  "pending",
  "completed",
  "failed",
  "cancelled"
]);
var transactions = pgTable("transactions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  walletId: integer("wallet_id").references(() => wallets.id).notNull(),
  type: transactionTypeEnum("type").notNull(),
  status: transactionStatusEnum("status").default("pending").notNull(),
  amount: decimal("amount", { precision: 18, scale: 8 }).notNull(),
  currency: text("currency").notNull(),
  txHash: text("tx_hash"),
  description: text("description"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var usersRelations = relations(users, ({ many }) => ({
  wallets: many(wallets),
  transactions: many(transactions)
}));
var walletsRelations = relations(wallets, ({ one, many }) => ({
  user: one(users, {
    fields: [wallets.userId],
    references: [users.id]
  }),
  transactions: many(transactions)
}));
var transactionsRelations = relations(transactions, ({ one }) => ({
  user: one(users, {
    fields: [transactions.userId],
    references: [users.id]
  }),
  wallet: one(wallets, {
    fields: [transactions.walletId],
    references: [wallets.id]
  })
}));
var insertUserSchema = createInsertSchema(users);
var selectUserSchema = createSelectSchema(users);
var insertWalletSchema = createInsertSchema(wallets);
var selectWalletSchema = createSelectSchema(wallets);
var insertTransactionSchema = createInsertSchema(transactions);
var selectTransactionSchema = createSelectSchema(transactions);

// db/index.ts
import dotenv from "dotenv";
dotenv.config({
  path: ".env"
});
neonConfig.webSocketConstructor = ws;
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var pool = new Pool({ connectionString: process.env.DATABASE_URL });
var db = drizzle({ client: pool, schema: schema_exports });

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { eq } from "drizzle-orm";
import { fromZodError } from "zod-validation-error";
var scryptAsync = promisify(scrypt);
var PostgresSessionStore = connectPg(session);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
async function getUserByUsername(username) {
  return db.select().from(users).where(eq(users.username, username)).limit(1);
}
async function getUserByEmail(email) {
  return db.select().from(users).where(eq(users.email, email)).limit(1);
}
function setupAuth(app2) {
  const sessionSecret = process.env.SESSION_SECRET || randomBytes(32).toString("hex");
  const store = new PostgresSessionStore({
    pool,
    createTableIfMissing: true,
    tableName: "session"
  });
  const sessionSettings = {
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1e3,
      // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const isEmail = /\S+@\S+\.\S+/.test(username);
        let user;
        if (isEmail) {
          [user] = await getUserByEmail(username);
        } else {
          [user] = await getUserByUsername(username);
        }
        if (!user || !await comparePasswords(password, user.password)) {
          return done(null, false, { message: "Invalid username or password" });
        } else {
          return done(null, user);
        }
      } catch (error) {
        return done(error);
      }
    })
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
      if (!user) {
        return done(null, false);
      }
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        const error = fromZodError(result.error);
        return res.status(400).json({ error: error.toString() });
      }
      const [existingUsername] = await getUserByUsername(result.data.username);
      if (existingUsername) {
        return res.status(400).json({ error: "Username already exists" });
      }
      const [existingEmail] = await getUserByEmail(result.data.email);
      if (existingEmail) {
        return res.status(400).json({ error: "Email already exists" });
      }
      const [user] = await db.insert(users).values({
        ...result.data,
        password: await hashPassword(result.data.password)
      }).returning();
      req.login(user, (err) => {
        if (err) return next(err);
        const { password, ...safeUser } = user;
        res.status(201).json(safeUser);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return res.status(401).json({ error: info?.message || "Invalid credentials" });
      }
      req.login(user, (loginErr) => {
        if (loginErr) {
          return next(loginErr);
        }
        const { password, ...safeUser } = user;
        return res.status(200).json(safeUser);
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      req.session.destroy((sessionErr) => {
        if (sessionErr) {
          return next(sessionErr);
        }
        res.clearCookie("connect.sid");
        res.sendStatus(200);
      });
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { password, ...safeUser } = req.user;
    res.json(safeUser);
  });
  app2.post("/api/become-admin", async (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { adminCode } = req.body;
    if (adminCode !== process.env.ADMIN_SECRET || !process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Invalid admin code" });
    }
    try {
      const [updatedUser] = await db.update(users).set({
        isAdmin: true,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq(users.id, req.user.id)).returning();
      req.user.isAdmin = true;
      const { password, ...safeUser } = updatedUser;
      res.json(safeUser);
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/wallets/setup", async (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    try {
      const existingWallets = await db.query.wallets.findMany({
        where: eq(users.id, req.user.id)
      });
      if (existingWallets.length > 0) {
        return res.status(400).json({ error: "User already has wallets" });
      }
      const currencies = ["BTC", "ETH", "USDT"];
      const walletsToCreate = currencies.map((currency) => ({
        userId: req.user.id,
        currency,
        balance: "0",
        address: generateWalletAddress(currency)
        // You would implement this function
      }));
      const createdWallets = await db.transaction(async (tx) => {
        return Promise.all(walletsToCreate.map(
          (wallet) => tx.insert(wallets).values(wallet).returning()
        ));
      });
      res.status(201).json({ wallets: createdWallets.flat() });
    } catch (error) {
      next(error);
    }
  });
}
function generateWalletAddress(currency) {
  const prefix = currency === "BTC" ? "1" : currency === "ETH" ? "0x" : "";
  return prefix + randomBytes(20).toString("hex");
}

// server/routes.ts
import { eq as eq3, and as and2, desc as desc2 } from "drizzle-orm";

// client/src/lib/crypto-data.ts
var cryptocurrencies = [
  {
    id: "bitcoin",
    name: "Bitcoin",
    symbol: "BTC",
    price: 61245.08,
    change24h: 2.34,
    marketCap: 1203845762345,
    volume24h: 38762453987
  },
  {
    id: "ethereum",
    name: "Ethereum",
    symbol: "ETH",
    price: 3189.42,
    change24h: 1.67,
    marketCap: 382736453876,
    volume24h: 15673452345
  },
  {
    id: "polygon",
    name: "Polygon",
    symbol: "MATIC",
    price: 1.23,
    change24h: -0.87,
    marketCap: 12736453876,
    volume24h: 1527345234
  },
  {
    id: "tether",
    name: "Tether",
    symbol: "USDT",
    price: 1,
    change24h: 0.01,
    marketCap: 92736453876,
    volume24h: 55673452345
  },
  {
    id: "solana",
    name: "Solana",
    symbol: "SOL",
    price: 104.65,
    change24h: 5.23,
    marketCap: 45673452345,
    volume24h: 7536453876
  }
];
var generateOrderBook = (currentPrice, depth = 5) => {
  const buyOrders = [];
  const sellOrders = [];
  for (let i = 0; i < depth; i++) {
    const price = currentPrice + currentPrice * (Math.random() * 1e-3 * (i + 1));
    const amount = Math.random() * 2;
    const total = price * amount;
    sellOrders.push({
      price,
      amount,
      total
    });
  }
  for (let i = 0; i < depth; i++) {
    const price = currentPrice - currentPrice * (Math.random() * 1e-3 * (i + 1));
    const amount = Math.random() * 2;
    const total = price * amount;
    buyOrders.push({
      price,
      amount,
      total
    });
  }
  sellOrders.sort((a, b) => a.price - b.price);
  buyOrders.sort((a, b) => b.price - a.price);
  return { buyOrders, sellOrders };
};
var generateTradeHistory = (currentPrice, count = 5) => {
  const trades = [];
  for (let i = 0; i < count; i++) {
    const isUp = Math.random() > 0.5;
    const price = currentPrice * (1 + (Math.random() * 0.01 - 5e-3));
    const amount = Math.random() * 0.5;
    const total = price * amount;
    const now = /* @__PURE__ */ new Date();
    now.setSeconds(now.getSeconds() - i * Math.floor(Math.random() * 60));
    const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    trades.push({
      id: `trade-${i}`,
      price,
      amount,
      total,
      type: isUp ? "buy" : "sell",
      time
    });
  }
  return trades;
};
var miningRigs = [
  {
    id: "rig-01",
    name: "Rig-01",
    status: "online",
    hashrate: 12.4,
    temperature: 62,
    earnings: 32e-5
  },
  {
    id: "rig-02",
    name: "Rig-02",
    status: "online",
    hashrate: 11.8,
    temperature: 58,
    earnings: 31e-5
  },
  {
    id: "rig-03",
    name: "Rig-03",
    status: "offline",
    hashrate: 0,
    temperature: 0,
    earnings: 0
  },
  {
    id: "rig-04",
    name: "Rig-04",
    status: "online",
    hashrate: 12.7,
    temperature: 64,
    earnings: 33e-5
  },
  {
    id: "rig-05",
    name: "Rig-05",
    status: "online",
    hashrate: 12.2,
    temperature: 61,
    earnings: 32e-5
  }
];
var portfolioAssets = [
  {
    id: "bitcoin",
    name: "Bitcoin",
    symbol: "BTC",
    balance: 0.31482,
    value: 19280.95,
    price: 61245.08,
    change24h: 2.34
  },
  {
    id: "ethereum",
    name: "Ethereum",
    symbol: "ETH",
    balance: 1.24561,
    value: 3972.81,
    price: 3189.42,
    change24h: 1.67
  },
  {
    id: "tether",
    name: "Tether",
    symbol: "USDT",
    balance: 5221.58,
    value: 5221.58,
    price: 1,
    change24h: 0.01
  }
];
var recentActivity = [
  {
    id: "activity-1",
    type: "buy",
    asset: "BTC",
    amount: 0.0124,
    value: 759.44,
    time: "2 hours ago"
  },
  {
    id: "activity-2",
    type: "mining",
    asset: "BTC",
    amount: 32e-5,
    value: 19.6,
    time: "6 hours ago"
  },
  {
    id: "activity-3",
    type: "sell",
    asset: "ETH",
    amount: 0.5,
    value: 1594.71,
    time: "1 day ago"
  },
  {
    id: "activity-4",
    type: "deposit",
    asset: "USDT",
    amount: 1e3,
    value: 1e3,
    time: "3 days ago"
  }
];

// server/routes/admin.ts
import { Router } from "express";

// server/middleware/admin.ts
function isAdmin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: "Access denied. Admin privileges required." });
  }
  next();
}

// server/routes/admin.ts
import { eq as eq2, asc, desc } from "drizzle-orm";
var router = Router();
router.use(isAdmin);
router.get("/users", async (req, res) => {
  try {
    const allUsers = await db.select().from(users).orderBy(asc(users.username));
    res.json(allUsers);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});
router.get("/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const [user] = await db.select().from(users).where(eq2(users.id, userId));
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});
router.patch("/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { username, email, firstName, lastName, isVerified, kycStatus, isAdmin: isAdmin2 } = req.body;
    const [existingUser] = await db.select().from(users).where(eq2(users.id, userId));
    if (!existingUser) {
      return res.status(404).json({ error: "User not found" });
    }
    const [updatedUser] = await db.update(users).set({
      username: username || existingUser.username,
      email: email || existingUser.email,
      firstName: firstName !== void 0 ? firstName : existingUser.firstName,
      lastName: lastName !== void 0 ? lastName : existingUser.lastName,
      isVerified: isVerified !== void 0 ? isVerified : existingUser.isVerified,
      kycStatus: kycStatus || existingUser.kycStatus,
      isAdmin: isAdmin2 !== void 0 ? isAdmin2 : existingUser.isAdmin,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq2(users.id, userId)).returning();
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Failed to update user" });
  }
});
router.get("/wallets", async (req, res) => {
  try {
    const allWallets = await db.select().from(wallets).orderBy(asc(wallets.userId));
    res.json(allWallets);
  } catch (error) {
    console.error("Error fetching wallets:", error);
    res.status(500).json({ error: "Failed to fetch wallets" });
  }
});
router.get("/wallets/:id", async (req, res) => {
  try {
    const walletId = parseInt(req.params.id);
    const [wallet] = await db.select().from(wallets).where(eq2(wallets.id, walletId));
    if (!wallet) {
      return res.status(404).json({ error: "Wallet not found" });
    }
    res.json(wallet);
  } catch (error) {
    console.error("Error fetching wallet:", error);
    res.status(500).json({ error: "Failed to fetch wallet" });
  }
});
router.patch("/wallets/:id", async (req, res) => {
  try {
    const walletId = parseInt(req.params.id);
    const { balance, address } = req.body;
    const [existingWallet] = await db.select().from(wallets).where(eq2(wallets.id, walletId));
    if (!existingWallet) {
      return res.status(404).json({ error: "Wallet not found" });
    }
    const [updatedWallet] = await db.update(wallets).set({
      balance: balance !== void 0 ? balance : existingWallet.balance,
      address: address || existingWallet.address,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq2(wallets.id, walletId)).returning();
    res.json(updatedWallet);
  } catch (error) {
    console.error("Error updating wallet:", error);
    res.status(500).json({ error: "Failed to update wallet" });
  }
});
router.get("/transactions", async (req, res) => {
  try {
    const allTransactions = await db.select().from(transactions).orderBy(desc(transactions.createdAt));
    res.json(allTransactions);
  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});
router.get("/transactions/:id", async (req, res) => {
  try {
    const transactionId = parseInt(req.params.id);
    const [transaction] = await db.select().from(transactions).where(eq2(transactions.id, transactionId));
    if (!transaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }
    res.json(transaction);
  } catch (error) {
    console.error("Error fetching transaction:", error);
    res.status(500).json({ error: "Failed to fetch transaction" });
  }
});
router.patch("/transactions/:id", async (req, res) => {
  try {
    const transactionId = parseInt(req.params.id);
    const { status, amount, txHash, description } = req.body;
    const [existingTransaction] = await db.select().from(transactions).where(eq2(transactions.id, transactionId));
    if (!existingTransaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }
    const [updatedTransaction] = await db.update(transactions).set({
      status: status || existingTransaction.status,
      amount: amount !== void 0 ? amount : existingTransaction.amount,
      txHash: txHash !== void 0 ? txHash : existingTransaction.txHash,
      description: description !== void 0 ? description : existingTransaction.description,
      updatedAt: /* @__PURE__ */ new Date()
    }).where(eq2(transactions.id, transactionId)).returning();
    res.json(updatedTransaction);
  } catch (error) {
    console.error("Error updating transaction:", error);
    res.status(500).json({ error: "Failed to update transaction" });
  }
});
var admin_default = router;

// server/routes.ts
function registerRoutes(app2) {
  setupAuth(app2);
  app2.use("/api/admin", admin_default);
  app2.get("/api/crypto", (_req, res) => {
    res.json(cryptocurrencies);
  });
  app2.get("/api/crypto/:symbol", (req, res) => {
    const symbol = req.params.symbol.toUpperCase();
    const crypto = cryptocurrencies.find((c) => c.symbol === symbol);
    if (!crypto) {
      return res.status(404).json({ message: "Cryptocurrency not found" });
    }
    res.json(crypto);
  });
  app2.get("/api/orderbook/:baseSymbol/:quoteSymbol", (req, res) => {
    const baseSymbol = req.params.baseSymbol.toUpperCase();
    const quoteSymbol = req.params.quoteSymbol.toUpperCase();
    const baseCrypto = cryptocurrencies.find((c) => c.symbol === baseSymbol);
    if (!baseCrypto) {
      return res.status(404).json({ message: "Base cryptocurrency not found" });
    }
    const orderBook = generateOrderBook(baseCrypto.price);
    res.json(orderBook);
  });
  app2.get("/api/trades/:baseSymbol/:quoteSymbol", (req, res) => {
    const baseSymbol = req.params.baseSymbol.toUpperCase();
    const quoteSymbol = req.params.quoteSymbol.toUpperCase();
    const baseCrypto = cryptocurrencies.find((c) => c.symbol === baseSymbol);
    if (!baseCrypto) {
      return res.status(404).json({ message: "Base cryptocurrency not found" });
    }
    const tradeHistory = generateTradeHistory(baseCrypto.price);
    res.json(tradeHistory);
  });
  app2.get("/api/mining/rigs", (_req, res) => {
    res.json(miningRigs);
  });
  app2.get("/api/portfolio", (_req, res) => {
    res.json(portfolioAssets);
  });
  app2.get("/api/my/portfolio", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    try {
      const userWallets = await db.query.wallets.findMany({
        where: eq3(wallets.userId, req.user.id)
      });
      res.json(userWallets);
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  });
  app2.get("/api/activity", (_req, res) => {
    res.json(recentActivity);
  });
  app2.get("/api/my/transactions", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    try {
      const userTransactions = await db.select().from(transactions).where(eq3(transactions.userId, req.user.id)).orderBy(desc2(transactions.createdAt)).limit(10);
      res.json(userTransactions);
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  });
  app2.post("/api/deposit", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { walletId, amount, currency } = req.body;
    if (!walletId || !amount || !currency) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    try {
      const [userWallet] = await db.select().from(wallets).where(and2(
        eq3(wallets.id, walletId),
        eq3(wallets.userId, req.user.id),
        eq3(wallets.currency, currency)
      ));
      if (!userWallet) {
        return res.status(404).json({ error: "Wallet not found" });
      }
      const [transaction] = await db.insert(transactions).values({
        userId: req.user.id,
        walletId: userWallet.id,
        type: "deposit",
        status: "pending",
        amount,
        currency,
        description: `Deposit of ${amount} ${currency}`
      }).returning();
      res.status(201).json(transaction);
      setTimeout(async () => {
        try {
          await db.update(transactions).set({
            status: "completed",
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq3(transactions.id, transaction.id));
          const currentBalance = parseFloat(userWallet.balance.toString());
          const amountValue = parseFloat(amount);
          const newBalance = (currentBalance + amountValue).toString();
          await db.update(wallets).set({
            balance: newBalance,
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq3(wallets.id, userWallet.id));
        } catch (error) {
          console.error("Error auto-completing deposit:", error);
        }
      }, 1e4);
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  });
  app2.post("/api/withdraw", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { walletId, amount, currency, address } = req.body;
    if (!walletId || !amount || !currency || !address) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    try {
      const [userWallet] = await db.select().from(wallets).where(and2(
        eq3(wallets.id, walletId),
        eq3(wallets.userId, req.user.id),
        eq3(wallets.currency, currency)
      ));
      if (!userWallet) {
        return res.status(404).json({ error: "Wallet not found" });
      }
      if (parseFloat(userWallet.balance.toString()) < parseFloat(amount)) {
        return res.status(400).json({ error: "Insufficient balance" });
      }
      const [transaction] = await db.insert(transactions).values({
        userId: req.user.id,
        walletId: userWallet.id,
        type: "withdrawal",
        status: "pending",
        amount,
        currency,
        description: `Withdrawal of ${amount} ${currency} to ${address}`
      }).returning();
      const currentBalance = parseFloat(userWallet.balance.toString());
      const amountValue = parseFloat(amount);
      const newBalance = (currentBalance - amountValue).toString();
      await db.update(wallets).set({
        balance: newBalance,
        updatedAt: /* @__PURE__ */ new Date()
      }).where(eq3(wallets.id, userWallet.id));
      res.status(201).json(transaction);
      setTimeout(async () => {
        try {
          await db.update(transactions).set({
            status: "completed",
            updatedAt: /* @__PURE__ */ new Date()
          }).where(eq3(transactions.id, transaction.id));
        } catch (error) {
          console.error("Error auto-completing withdrawal:", error);
        }
      }, 1e4);
    } catch (error) {
      res.status(500).json({ error: "Server error" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express from "express";
import fs from "fs";
import path2, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  plugins: [react(), runtimeErrorOverlay(), themePlugin()],
  resolve: {
    alias: {
      "@db": path.resolve(__dirname, "db"),
      "@": path.resolve(__dirname, "client", "src")
    }
  },
  root: path.resolve(__dirname, "client"),
  build: {
    outDir: path.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: {
      middlewareMode: true,
      hmr: { server }
    },
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(`src="/src/main.tsx"`, `src="/src/main.tsx?v=${nanoid()}"`);
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path2.resolve(__dirname2, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/index.ts
dotenv2.config();
var app = express2();
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path3 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path3.startsWith("/api")) {
      let logLine = `${req.method} ${path3} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  const server = registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const PORT = 5e3;
  server.listen(PORT, "0.0.0.0", () => {
    log(`serving on port ${PORT}`);
  });
})();
