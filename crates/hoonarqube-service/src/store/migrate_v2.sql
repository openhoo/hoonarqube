ALTER TABLE analyses ADD COLUMN exact_floats INTEGER NOT NULL DEFAULT 0
    CHECK (exact_floats IN (0, 1));
