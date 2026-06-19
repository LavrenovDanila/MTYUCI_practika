from app import db
from datetime import datetime


class Recipe(db.Model):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    ingredients = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Recipe {self.title}>'

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'ingredients': self.ingredients,
            'instructions': self.instructions,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    @classmethod
    def search(cls, query):
        """Поиск по названию или ингредиентам (регистронезависимый)"""
        if not query:
            return cls.query.order_by(cls.created_at.desc()).all()
        return cls.query.filter(
            db.or_(
                cls.title.ilike(f'%{query}%'),
                cls.ingredients.ilike(f'%{query}%')
            )
        ).order_by(cls.created_at.desc()).all()