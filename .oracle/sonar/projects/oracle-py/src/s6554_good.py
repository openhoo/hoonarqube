class Invoice(models.Model):
    total = 0

    def __str__(self):
        return self.title
