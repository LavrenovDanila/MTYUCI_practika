from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length


class RecipeForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Описание')
    ingredients = TextAreaField('Ингредиенты', validators=[DataRequired()])
    instructions = TextAreaField('Инструкция приготовления', validators=[DataRequired()])
    submit = SubmitField('Сохранить')