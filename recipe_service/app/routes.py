from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from app import db
from app.models import Recipe
from app.forms import RecipeForm

bp = Blueprint('main', __name__)


# Вспомогательные функции для работы с избранным в сессии
def get_favorites():
    """Возвращает список id избранных рецептов из сессии"""
    return session.get('favorites', [])


def set_favorites(fav_list):
    session['favorites'] = fav_list
    session.modified = True


@bp.route('/')
def index():
    query = request.args.get('q', '')
    if query:
        recipes = Recipe.search(query)
    else:
        recipes = Recipe.query.order_by(Recipe.created_at.desc()).all()
    favorites = get_favorites()
    return render_template('index.html', recipes=recipes, favorites=favorites, query=query)


@bp.route('/favorites')
def favorites():
    fav_ids = get_favorites()
    recipes = Recipe.query.filter(Recipe.id.in_(fav_ids)).all() if fav_ids else []
    return render_template('favorites.html', recipes=recipes, favorites=fav_ids)


@bp.route('/favorite/toggle/<int:recipe_id>', methods=['POST'])
def toggle_favorite(recipe_id):
    fav = get_favorites()
    if recipe_id in fav:
        fav.remove(recipe_id)
        flash('Рецепт удалён из избранного', 'info')
    else:
        fav.append(recipe_id)
        flash('Рецепт добавлен в избранное', 'success')
    set_favorites(fav)
    return redirect(request.referrer or url_for('main.index'))


@bp.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    favorites = get_favorites()
    return render_template('recipe_detail.html', recipe=recipe, favorites=favorites)


@bp.route('/recipe/new', methods=['GET', 'POST'])
def new_recipe():
    form = RecipeForm()
    if form.validate_on_submit():
        recipe = Recipe(
            title=form.title.data,
            description=form.description.data,
            ingredients=form.ingredients.data,
            instructions=form.instructions.data
        )
        db.session.add(recipe)
        db.session.commit()
        flash('Рецепт успешно добавлен!', 'success')
        return redirect(url_for('main.recipe_detail', recipe_id=recipe.id))
    return render_template('recipe_form.html', form=form, title='Новый рецепт')


@bp.route('/recipe/<int:recipe_id>/edit', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    form = RecipeForm(obj=recipe)
    if form.validate_on_submit():
        recipe.title = form.title.data
        recipe.description = form.description.data
        recipe.ingredients = form.ingredients.data
        recipe.instructions = form.instructions.data
        db.session.commit()
        flash('Рецепт обновлён!', 'success')
        return redirect(url_for('main.recipe_detail', recipe_id=recipe.id))
    return render_template('recipe_form.html', form=form, title='Редактирование рецепта', recipe=recipe)


@bp.route('/recipe/<int:recipe_id>/delete', methods=['POST'])
def delete_recipe(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    db.session.delete(recipe)
    db.session.commit()
    flash('Рецепт удалён.', 'warning')
    return redirect(url_for('main.index'))

@bp.route('/api/recipes')
def api_recipes():

    recipes = Recipe.query.all()

    return {'recipes': [r.to_dict() for r in recipes]}