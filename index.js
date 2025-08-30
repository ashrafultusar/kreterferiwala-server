const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mongodb = require("mongodb");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const app = express();
const crypto = require("crypto");


const port = process.env.PORT || 5000;

app.use(cors());

// middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://kretarferiwala-server-seven.vercel.app",
    ],
    credentials: true,
  })
);

app.use(express.json());

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer config with Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "kretarferiwala/slider",
    allowed_formats: ["jpg", "jpeg", "png"],
  },
});
const upload = multer({ storage });

// JWT Authentication Middleware
function token(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ message: "Invalid or expired token" });

    req.user = user;
    next();
  });
}

async function run() {
  try {
    const allProducts = client.db("kfDB").collection("products");
    const allCategories = client.db("kfDB").collection("categories");
    const slider = client.db("kfDB").collection("sliderimages");
    const allOrders = client.db("kfDB").collection("orders");
    const deliveryCharge = client.db("kfDB").collection("deliverycharges");
    const sliderImages = client.db("kfDB").collection("sliderimages");
    const adminCollection = client.db("kfDB").collection("admin");

    // admin register
    app.post("/register", async (req, res) => {
      const { email, password } = req.body;

      const existingUser = await adminCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      // Check if this is the first user
      const userCount = await adminCollection.countDocuments();
      const role = userCount === 0 ? "superAdmin" : "admin";

      await adminCollection.insertOne({
        email,
        password: hashedPassword,
        role, // Assign role here
      });

      res.status(201).json({ message: "User registered successfully", role });
    });

    // admin login
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
        return res
          .status(400)
          .json({ message: "Email and password are required" });
      }

      const user = await adminCollection.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });

      res.json({ token });
    });

    // verify token
    app.get("/me", token, (req, res) => {
      res.json({ email: req.user.email });
    });

    // Upload a new slider image
    app.post("/slider", upload.single("image"), async (req, res) => {
      try {
        const imageUrl = req.file.path;
        const result = await sliderImages.insertOne({
          imageUrl,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
        const insertedImage = await sliderImages.findOne({
          _id: result.insertedId,
        });
        res.status(201).json(insertedImage);
      } catch (error) {
        console.error("Slider image upload error:", error);
        res.status(500).json({ error: "Failed to upload slider image" });
      }
    });

    // Delete a slider image
    app.delete("/sliderDelete", async (req, res) => {
      const { id } = req.query;
      if (!id) return res.status(400).json({ error: "Missing image ID" });

      try {
        const sliderImage = await sliderImages.findOne({
          _id: new ObjectId(id),
        });

        if (!sliderImage) {
          return res.status(404).json({ error: "Image not found" });
        }

        const public_id = sliderImage.imageUrl.split("/").pop().split(".")[0];
        await cloudinary.uploader.destroy(public_id);

        await sliderImages.deleteOne({ _id: new ObjectId(id) });

        res.status(200).json({ message: "Image deleted successfully" });
      } catch (err) {
        console.error("Error deleting image:", err);
        res.status(500).json({ error: "Failed to delete image" });
      }
    });

    app.post("/products", upload.array("images", 10), async (req, res) => {
      try {
        if (!req.files || req.files.length === 0) {
          return res.status(400).json({ message: "No images uploaded" });
        }

        let { name, category, description, regularPrice, discountPrice } =
          req.body;

        // Make sure category is always an array
        if (!Array.isArray(category)) {
          category = [category];
        }

        const imageUrls = req.files.map((file) => file.path);

        const newProduct = {
          name,
          category,
          description,
          regularPrice,
          discountPrice,
          images: imageUrls,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await allProducts.insertOne(newProduct);

        res.status(201).json({
          message: "Product added successfully",
          product: newProduct,
          insertedId: result.insertedId,
        });
      } catch (error) {
        console.error("Error adding product:", error);
        res
          .status(500)
          .json({ message: "Failed to add product", error: error.message });
      }
    });

    app.patch("/products/:id", upload.array("images", 10), async (req, res) => {
      try {
        const { id } = req.params;
        let {
          name,
          category,
          description,
          regularPrice,
          discountPrice,
          existingImages,
        } = req.body;

        // Make sure category is always an array
        if (!Array.isArray(category)) {
          category = [category];
        }

        // Make sure existingImages is an array
        if (!existingImages) {
          existingImages = [];
        } else if (!Array.isArray(existingImages)) {
          existingImages = [existingImages];
        }

        // Add new uploaded images
        const newImageUrls = req.files
          ? req.files.map((file) => file.path)
          : [];

        // Combine existing and new images
        const images = [...existingImages, ...newImageUrls];

        const updatedProduct = {
          name,
          category,
          description,
          regularPrice,
          discountPrice,
          images,
          updatedAt: new Date(),
        };

        const result = await allProducts.updateOne(
          { _id: new mongodb.ObjectId(id) },
          { $set: updatedProduct }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: "Product not found" });
        }

        res.status(200).json({
          message: "Product updated successfully",
          product: updatedProduct,
        });
      } catch (error) {
        console.error("Error updating product:", error);
        res
          .status(500)
          .json({ message: "Failed to update product", error: error.message });
      }
    });

    //  all products fetch
    app.get("/products", async (req, res) => {
      try {
        await client.connect();

        const allPosts = await allProducts.find().toArray();

        res.json(allPosts);
      } catch (error) {
        console.error("Error fetching all posts:", error);
        res.status(500).json({ error: "Failed to fetch posts" });
      }
    });

    // id wise products fetch
    app.get("/productDetails/:id", async (req, res) => {
      const id = req.params.id;
      console.log(id);
      const query = { _id: new ObjectId(id) };
      const result = await allProducts.findOne(query);
      res.send(result);
    });

    //  all categories fetch
    app.get("/categories", async (req, res) => {
      try {
        await client.connect();

        const allPosts = await allCategories.find().toArray();

        res.json(allPosts);
      } catch (error) {
        console.error("Error fetching all posts:", error);
        res.status(500).json({ error: "Failed to fetch posts" });
      }
    });

    //   slider get
    app.get("/sliders", async (req, res) => {
      try {
        await client.connect();

        const allPosts = await slider.find().toArray();

        res.json(allPosts);
      } catch (error) {
        console.error("Error fetching all posts:", error);
        res.status(500).json({ error: "Failed to fetch posts" });
      }
    });

    // Update your /track-purchase route
    app.post("/track-purchase", async (req, res) => {
      try {
        const { orderId } = req.body;

        if (!orderId) {
          return res.status(400).json({ error: "orderId is required" });
        }

        // order ডাটাবেস থেকে বের করা
        const order = await client
          .db("kfDB")
          .collection("orders")
          .findOne({ _id: new ObjectId(orderId) });

        if (!order) {
          return res.status(404).json({ error: "Order not found" });
        }

        const pixelId = process.env.META_PIXEL_ID;
        const accessToken = process.env.META_ACCESS_TOKEN;

        // Payload তৈরি করা
        const payload = {
          data: [
            {
              event_name: "Purchase",
              event_time: Math.floor(
                new Date(order.createdAt).getTime() / 1000
              ),
              action_source: "website",
              event_source_url: "https://kretarferiwala.com.bd/checkout",

              user_data: {
                ph: [sha256(order.phone || "")],
                fn: [sha256(order.name?.split(" ")[0] || "")],
                ln: [sha256(order.name?.split(" ")[1] || "")],
                client_ip_address: req.ip,
                client_user_agent: req.headers["user-agent"],
              },

              custom_data: {
                currency: "BDT",
                value: order.totalAmount,
                order_id: order.orderNumber || String(order._id),
                contents: order.products.map((p) => ({
                  id: p.id,
                  quantity: p.quantity,
                  item_price: p.discountPrice,
                })),
                num_items: order.products.reduce(
                  (acc, p) => acc + p.quantity,
                  0
                ),
              },
            },
          ],
        };

        // Meta CAPI তে পাঠানো
        const response = await fetch(
          `https://graph.facebook.com/v20.0/${pixelId}/events?access_token=${accessToken}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        );

        const data = await response.json();

        res.status(200).json({
          success: true,
          message: "Purchase event sent successfully",
          fbResponse: data,
        });
      } catch (error) {
        console.error("Meta CAPI Error:", error);
        res.status(500).json({
          success: false,
          error: error.message,
        });
      }
    });

    // Order create route with auto Meta CAPI tracking
    app.post("/orders", async (req, res) => {
      try {
        const orderData = req.body;

        if (!orderData?.products || orderData.products.length === 0) {
          return res.status(400).json({ error: "No products in order" });
        }

        const generateOrderNumber = () => {
          const randomNum = Math.floor(100000 + Math.random() * 900000);
          return `GB#${randomNum}`;
        };

        const orderWithDefaults = {
          ...orderData,
          status: "active",
          paymentMethod: "Cash on Delivery",
          orderNumber: generateOrderNumber(),
          createdAt: new Date(),
        };

        // Save order
        const result = await allOrders.insertOne(orderWithDefaults);

        // --- Auto Track Purchase ---
        const pixelId = process.env.META_PIXEL_ID;
        const accessToken = process.env.META_ACCESS_TOKEN;

        const payload = {
          data: [
            {
              event_name: "Purchase",
              event_time: Math.floor(
                new Date(orderWithDefaults.createdAt).getTime() / 1000
              ),
              action_source: "website",
              event_source_url: "https://kretarferiwala.com.bd/checkout",

              user_data: {
                ph: [sha256(orderWithDefaults.phone || "")],
                fn: [sha256(orderWithDefaults.name?.split(" ")[0] || "")],
                ln: [sha256(orderWithDefaults.name?.split(" ")[1] || "")],
                client_ip_address: req.ip,
                client_user_agent: req.headers["user-agent"],
              },

              custom_data: {
                currency: "BDT",
                value: orderWithDefaults.totalAmount,
                order_id: orderWithDefaults.orderNumber,
                contents: orderWithDefaults.products.map((p) => ({
                  id: p.id,
                  quantity: p.quantity,
                  item_price: p.discountPrice,
                })),
                num_items: orderWithDefaults.products.reduce(
                  (acc, p) => acc + p.quantity,
                  0
                ),
              },
            },
          ],
        };

        // Send to Meta CAPI (fire-and-forget)
        fetch(
          `https://graph.facebook.com/v20.0/${pixelId}/events?access_token=${accessToken}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          }
        )
          .then((res) => res.json())
          .then((data) => console.log("Meta CAPI response:", data))
          .catch((err) => console.error("Meta CAPI error:", err));
       

        res.status(201).json({
          message: "Order placed successfully",
          insertedId: result.insertedId,
          orderNumber: orderWithDefaults.orderNumber,
        });
      } catch (error) {
        console.error("Error placing order:", error);
        res.status(500).json({ error: "Failed to place order" });
      }
    });


    // Delete order by ID with token middleware
    app.delete("/orders/:id", token, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await allOrders.deleteOne(query); // আপনার orders collection

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Order not found" });
        }

        res.json({ message: "Order deleted successfully" });
      } catch (error) {
        console.error("Error deleting order:", error);
        res.status(500).json({ message: "Failed to delete order" });
      }
    });

    // related products fetch
    app.get("/related-products", async (req, res) => {
      try {
        const category = req.query.category;
        const excludeId = req.query.excludeId;

        if (!category || !excludeId) {
          return res
            .status(400)
            .json({ error: "category and excludeId are required" });
        }

        const query = {
          category: category,
          _id: { $ne: new ObjectId(excludeId) },
        };

        const relatedProducts = await allProducts.find(query).toArray();
        res.json(relatedProducts);
      } catch (error) {
        console.error("Error fetching related products:", error);
        res.status(500).json({ error: "Failed to fetch related products" });
      }
    });

    // get all order
    app.get("/allOrders", async (req, res) => {
      try {
        await client.connect();

        const allPosts = await allOrders.find().toArray();

        res.json(allPosts);
      } catch (error) {
        console.error("Error fetching all posts:", error);
        res.status(500).json({ error: "Failed to fetch posts" });
      }
    });

    // Update order status
    app.patch("/orders/:id", async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        if (!status) {
          return res.status(400).json({ error: "Status is required" });
        }

        const result = await allOrders.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .json({ error: "Order not found or already updated" });
        }

        res.status(200).json({
          message: "Order status updated successfully",
          data: { status },
        });
      } catch (error) {
        console.error("Failed to update order status:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.get("/orders/:id", async (req, res) => {
      const id = req.params.id;
      console.log(id);
      const query = { _id: new ObjectId(id) };
      const result = await allOrders.findOne(query);
      res.send(result);
    });

    // DELETE product by ID
    app.delete("/product/:id", token, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await allProducts.deleteOne(query);

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Product not found" });
        }

        res.json({ message: "Product deleted successfully" });
      } catch (error) {
        console.error("Error deleting product:", error);
        res.status(500).json({ message: "Failed to delete product" });
      }
    });

    // delivery charge
    app.get("/updatedeliverycharge", async (req, res) => {
      try {
        const chargeData = await deliveryCharge.findOne({});

        if (!chargeData) {
          return res.status(404).json({ error: "Delivery charge not found" });
        }

        res.json({
          insideDhaka: chargeData.insideDhaka,
          outsideDhaka: chargeData.outsideDhaka,
        });
      } catch (error) {
        console.error("Error fetching delivery charge:", error);
        res.status(500).json({ error: "Failed to fetch delivery charge" });
      }
    });

    app.patch("/updatedeliverycharge", token, async (req, res) => {
      try {
        const { insideDhaka, outsideDhaka } = req.body;

        if (
          typeof insideDhaka !== "number" ||
          typeof outsideDhaka !== "number" ||
          insideDhaka < 0 ||
          outsideDhaka < 0
        ) {
          return res.status(400).json({ error: "Invalid delivery charges" });
        }

        let chargeData = await deliveryCharge.findOne({});
        if (!chargeData) {
          chargeData = {
            insideDhaka,
            outsideDhaka,
            createdAt: new Date(),
            updatedAt: new Date(),
          };
          await deliveryCharge.insertOne(chargeData);
        } else {
          await deliveryCharge.updateOne(
            { _id: chargeData._id },
            {
              $set: {
                insideDhaka,
                outsideDhaka,
                updatedAt: new Date(),
              },
            }
          );
        }

        res
          .status(200)
          .json({ message: "Delivery charges updated successfully" });
      } catch (error) {
        console.error("Error updating delivery charge:", error);
        res.status(500).json({ error: "Failed to update delivery charge" });
      }
    });

    // Create a new category
    app.post("/category", upload.single("image"), async (req, res) => {
      const { name } = req.body;
      const image = req.file?.path;

      try {
        if (!name || !image) {
          return res
            .status(400)
            .json({ error: "Category name and image are required" });
        }

        const result = await allCategories.insertOne({
          name,
          image,
          createdAt: new Date(),
          updatedAt: new Date(),
        });

        const newCategory = await allCategories.findOne({
          _id: result.insertedId,
        });
        res.status(201).json(newCategory);
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to create category" });
      }
    });

    // Delete a category by ID
    app.delete("/category/:id", async (req, res) => {
      const { id } = req.params;

      try {
        const category = await allCategories.findOne({ _id: new ObjectId(id) });

        if (!category) {
          return res.status(404).json({ error: "Category not found" });
        }
        const public_id = category.image.split("/").pop().split(".")[0];
        await cloudinary.uploader.destroy(public_id);

        await allCategories.deleteOne({ _id: new ObjectId(id) });

        res.status(200).json({ message: "Category deleted successfully" });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to delete category" });
      }
    });

    // Search route
    app.get("/products", async (req, res) => {
      try {
        const query = req.query.query || "";
        if (!query.trim()) {
          return res.json([]);
        }

        const regex = new RegExp(query, "i");
        const products = await allProducts
          .find({ name: { $regex: regex } })
          .toArray();

        res.json(products);
      } catch (error) {
        console.error("Fetch error:", error);
        res.status(500).json({ error: "Failed to fetch products" });
      }
    });

    //  all categories fetch
    app.get("/allAdmin", async (req, res) => {
      try {
        await client.connect();

        const allPosts = await adminCollection.find().toArray();

        res.json(allPosts);
      } catch (error) {
        console.error("Error fetching all posts:", error);
        res.status(500).json({ error: "Failed to fetch posts" });
      }
    });

    // admin delete
    app.delete("/admin/:id", async (req, res) => {
      const { id } = req.params;

      try {
        // Convert id string to ObjectId to query MongoDB
        const { ObjectId } = require("mongodb");
        const objectId = new ObjectId(id);

        const result = await adminCollection.deleteOne({ _id: objectId });

        if (result.deletedCount === 1) {
          res.status(200).json({ message: "Category deleted successfully" });
        } else {
          res.status(404).json({ error: "Category not found" });
        }
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to delete category" });
      }
    });

    // PATCH /admin/:id/role
    app.patch("/admin/:id/role", async (req, res) => {
      const { id } = req.params;
      const { role } = req.body;

      if (!["admin", "superAdmin"].includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      try {
        await adminCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { role } }
        );
        res.status(200).json({ message: "Role updated successfully" });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Failed to update role" });
      }
    });

    // this code is not important

    // Connect the client to the server	(optional starting in v4.7)

    // await client.connect();
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    // console.log(
    //   "Pinged your deployment. You successfully connected to MongoDB!"
    // );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("kretarferiwala is running");
});

app.listen(port, () => {
  console.log(`kretarferiwala is running on port ${port}`);
});
