import express from "express";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import db from "./src/db.ts";
import Stripe from "stripe";

dotenv.config();

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_placeholder");

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // --- Middleware ---
  const protect = (req: any, res: any, next: any) => {
    let token = req.headers.authorization;
    if (token && token.startsWith("Bearer")) {
      try {
        token = token.split(" ")[1];
        const decoded: any = jwt.verify(token, process.env.JWT_SECRET || "secret");
        req.user = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(decoded.id);
        next();
      } catch (error) {
        res.status(401).json({ message: "Not authorized, token failed" });
      }
    } else {
      res.status(401).json({ message: "Not authorized, no token" });
    }
  };

  const admin = (req: any, res: any, next: any) => {
    if (req.user && req.user.role === "admin") {
      next();
    } else {
      res.status(401).json({ message: "Not authorized as an admin" });
    }
  };

  // --- Auth Routes ---
  app.post("/api/users/login", (req, res) => {
    const { email, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (user && bcrypt.compareSync(password, user.password)) {
      res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        token: jwt.sign({ id: user.id }, process.env.JWT_SECRET || "secret", { expiresIn: "30d" }),
      });
    } else {
      res.status(401).json({ message: "Invalid email or password" });
    }
  });

  app.post("/api/users/register", (req, res) => {
    const { name, email, password } = req.body;
    const userExists = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db.prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)").run(name, email, hashedPassword);
    
    const user: any = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(result.lastInsertRowid);

    res.status(201).json({
      ...user,
      token: jwt.sign({ id: user.id }, process.env.JWT_SECRET || "secret", { expiresIn: "30d" }),
    });
  });

  // --- Product Routes ---
  app.get("/api/products", (req, res) => {
    const products = db.prepare("SELECT * FROM products ORDER BY createdAt DESC").all();
    res.json(products.map((p: any) => ({ ...p, images: JSON.parse(p.images || "[]") })));
  });

  app.get("/api/products/:id", (req, res) => {
    const product: any = db.prepare("SELECT * FROM products WHERE id = ?").get(req.params.id);
    if (product) {
      res.json({ ...product, images: JSON.parse(product.images || "[]") });
    } else {
      res.status(404).json({ message: "Product not found" });
    }
  });

  app.post("/api/products", protect, admin, (req, res) => {
    const { name, price, description, images, category, brand, stock } = req.body;
    const result = db.prepare(
      "INSERT INTO products (name, price, description, images, category, brand, stock) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).run(name, price, description, JSON.stringify(images), category, brand, stock);
    res.status(201).json({ id: result.lastInsertRowid });
  });

  // --- Order Routes ---
  app.post("/api/orders", protect, (req: any, res) => {
    const { orderItems, shippingAddress, paymentMethod, totalPrice } = req.body;
    const result = db.prepare(
      "INSERT INTO orders (userId, orderItems, shippingAddress, paymentMethod, totalPrice) VALUES (?, ?, ?, ?, ?)"
    ).run(req.user.id, JSON.stringify(orderItems), JSON.stringify(shippingAddress), paymentMethod, totalPrice);
    res.status(201).json({ id: result.lastInsertRowid });
  });

  app.get("/api/orders/myorders", protect, (req: any, res) => {
    const orders = db.prepare("SELECT * FROM orders WHERE userId = ?").all(req.user.id);
    res.json(orders.map((o: any) => ({
      ...o,
      orderItems: JSON.parse(o.orderItems),
      shippingAddress: JSON.parse(o.shippingAddress)
    })));
  });

  // --- Stripe Payment ---
  app.post("/api/payment/create-intent", protect, async (req, res) => {
    const { amount } = req.body;
    try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: "usd",
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    } catch (error: any) {
      res.status(500).json({ message: error.message });
    }
  });

  // Seed initial data if empty
  const userCount: any = db.prepare("SELECT COUNT(*) as count FROM users").get();
  if (userCount.count === 0) {
    const adminPass = bcrypt.hashSync("admin123", 10);
    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run("Admin User", "admin@example.com", adminPass, "admin");
  }

  const productCount: any = db.prepare("SELECT COUNT(*) as count FROM products").get();
  if (productCount.count < 20) {
    // Clear existing products to ensure accurate images are applied as requested
    db.prepare("DELETE FROM products").run();
    
    const products = [
      { 
        name: "iPhone 15 Pro", 
        price: 999, 
        category: "Smartphones", 
        brand: "Apple", 
        stock: 10, 
        images: ["https://images.unsplash.com/photo-1695048133142-1a20484d2569?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Samsung Galaxy S23 Ultra", 
        price: 1199, 
        category: "Smartphones", 
        brand: "Samsung", 
        stock: 8, 
        images: ["https://images.unsplash.com/photo-1678911820864-e2c567c655d7?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Google Pixel 8 Pro", 
        price: 999, 
        category: "Smartphones", 
        brand: "Google", 
        stock: 6, 
        images: ["https://images.unsplash.com/photo-1696446701796-da61225697cc?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "MacBook Pro 14 M3", 
        price: 1599, 
        category: "Laptops", 
        brand: "Apple", 
        stock: 5, 
        images: ["https://images.unsplash.com/photo-1517336714731-489689fd1ca8?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Dell XPS 15", 
        price: 1899, 
        category: "Laptops", 
        brand: "Dell", 
        stock: 4, 
        images: ["https://images.unsplash.com/photo-1593642632823-8f785ba67e45?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Razer Blade 16", 
        price: 2999, 
        category: "Laptops", 
        brand: "Razer", 
        stock: 3, 
        images: ["https://images.unsplash.com/photo-1525547719571-a2d4ac8945e2?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Sony WH-1000XM5", 
        price: 399, 
        category: "Headphones", 
        brand: "Sony", 
        stock: 15, 
        images: ["https://images.unsplash.com/photo-1618366712010-f4ae9c647dcb?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "AirPods Max Silver", 
        price: 549, 
        category: "Headphones", 
        brand: "Apple", 
        stock: 10, 
        images: ["https://images.unsplash.com/photo-1613040809024-b4ef7ba99bc3?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Bose QuietComfort Ultra", 
        price: 429, 
        category: "Headphones", 
        brand: "Bose", 
        stock: 12, 
        images: ["https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Rolex Submariner Date", 
        price: 10500, 
        category: "Watches", 
        brand: "Rolex", 
        stock: 2, 
        images: ["https://images.unsplash.com/photo-1547996160-81dfa63595aa?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Omega Speedmaster", 
        price: 6300, 
        category: "Watches", 
        brand: "Omega", 
        stock: 3, 
        images: ["https://images.unsplash.com/photo-1614164185128-e4ec99c436d7?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Apple Watch Ultra 2", 
        price: 799, 
        category: "Watches", 
        brand: "Apple", 
        stock: 7, 
        images: ["https://images.unsplash.com/photo-1695048133142-1a20484d2569?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Nike Air Jordan 1 Retro", 
        price: 180, 
        category: "Sneakers", 
        brand: "Nike", 
        stock: 20, 
        images: ["https://images.unsplash.com/photo-1597045566774-bf1929c0933e?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Adidas Yeezy Boost 350 V2", 
        price: 230, 
        category: "Sneakers", 
        brand: "Adidas", 
        stock: 12, 
        images: ["https://images.unsplash.com/photo-1595950653106-6c9ebd614d3a?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "New Balance 990v6", 
        price: 200, 
        category: "Sneakers", 
        brand: "New Balance", 
        stock: 15, 
        images: ["https://images.unsplash.com/photo-1539185441755-769473a23570?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "PlayStation 5 Console", 
        price: 499, 
        category: "Gaming", 
        brand: "Sony", 
        stock: 5, 
        images: ["https://images.unsplash.com/photo-1606813907291-d86efa9b94db?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Nintendo Switch OLED", 
        price: 349, 
        category: "Gaming", 
        brand: "Nintendo", 
        stock: 10, 
        images: ["https://images.unsplash.com/photo-1578303512597-81e6cc155b3e?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "Canon EOS R5", 
        price: 3899, 
        category: "Cameras", 
        brand: "Canon", 
        stock: 2, 
        images: ["https://images.unsplash.com/photo-1516035069371-29a1b244cc32?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "DJI Mavic 3 Pro", 
        price: 2199, 
        category: "Drones", 
        brand: "DJI", 
        stock: 4, 
        images: ["https://images.unsplash.com/photo-1473968512647-3e447244af8f?auto=format&fit=crop&q=80&w=800"] 
      },
      { 
        name: "iPad Pro 12.9 M2", 
        price: 1099, 
        category: "Tablets", 
        brand: "Apple", 
        stock: 8, 
        images: ["https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?auto=format&fit=crop&q=80&w=800"] 
      },
    ];

    products.forEach(p => {
      db.prepare("INSERT INTO products (name, price, description, images, category, brand, stock) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(p.name, p.price, `${p.name} - Premium quality ${p.category.toLowerCase()} from ${p.brand}.`, JSON.stringify(p.images), p.category, p.brand, p.stock);
    });
  }

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
