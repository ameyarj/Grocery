<template>
  <v-carousel
    cycle
    hide-delimiter-background
    show-arrows-on-hover
    height="180"
    :value="selectedCategoryIndex"
    @input="categorySlideChanged"
  >
    <v-carousel-item
      v-for="(category, index) in categories"
      :key="index"
      :value="index"
    >
      <v-card
        :color="isActiveCategory(category.title) ? '#D5F0DB' : 'white'"
        :class="isActiveCategory(category.title) ? 'borderme' : 'borderout'"
        class="d-flex align-center rounded-lg mx-2"
        dark
        height="180"
        @click="categoryClicked(category.title)"
        flat
      >


              <v-row>
                <v-col cols="12" sm="12">
                  <v-list-item three-line class="text-center">
                    <v-list-item-content>
                      <div align="center" justify="center">
                        <v-img
                          :src="getImageURL(category)"
                          max-height="80"
                          max-width="80"
                          contain
                        ></v-img>
                      </div>
                      <v-list-item-subtitle
                        :class="active ? 'green--text' : 'black--text'"
                        class="caption mt-4"
                      >
                        {{ category.title }}
                      </v-list-item-subtitle>
                    </v-list-item-content>
                  </v-list-item>
                </v-col>
              </v-row>
            </v-card>
    </v-carousel-item>
  </v-carousel>
</template>

<script>
export default {
  data: () => ({
    categories: [],
    selectedCategory: null,
    selectedCategoryIndex: 0,
    active: false,

  }),
  created() {
    this.fetchCategories();
  },
  methods: {
    categoryClicked(categoryTitle) {
      this.selectedCategory = categoryTitle;
      this.active = true;
      this.$emit('category-selected', categoryTitle); 
    },
    categorySlideChanged(index) {
      this.selectedCategoryIndex = index;
      this.selectedCategory = this.categories[index].title;
      this.active = true;
      this.$emit('category-selected', this.selectedCategory);
    },

    isActiveCategory(categoryTitle) {
      return this.selectedCategory === categoryTitle;
    },
    async fetchCategories() {
      try {
        const response = await fetch("http://localhost:5000/api/categories");
        if (response.ok) {
          const data = await response.json();
          this.categories = data;
        } else {
          console.error("Failed to fetch categories:", response.status);
        }
      } catch (error) {
        console.error("An error occurred while fetching categories:", error);
      }
    },
    getImageURL(category) {
      return category.image_filename || 'C:\\Users\\DELL\\OneDrive\\Desktop\\mad2_project\\egrocery\\public\\default-image.jpeg';
    },
  },
};
</script>

<style>
</style>
