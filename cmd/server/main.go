package main

import (
	"flag"
	"log"
	"os"

	"ducksrow/backend/database"
	"ducksrow/backend/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
)

func main() {
	seedOnly := flag.Bool("seed-admin", false, "run admin seed only and exit")
	flag.Parse()

	// Load .env from current directory (backend/ when run from repo root or backend)
	_ = godotenv.Load()

	db, err := database.Connect()
	if err != nil {
		log.Fatalf("database connect: %v", err)
	}

	if err := database.Migrate(db); err != nil {
		log.Fatalf("database migrate: %v", err)
	}

	if err := database.SeedAdmin(db); err != nil {
		log.Fatalf("seed admin: %v", err)
	}

	if *seedOnly {
		log.Println("Admin seed done, exiting.")
		return
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"error": err.Error()})
		},
	})

	app.Use(recover.New())
	app.Use(logger.New())

	routes.Setup(app, db)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server listening on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
