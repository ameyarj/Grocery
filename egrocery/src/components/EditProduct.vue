<template>
    <div>
      <Navbar />
      <h2>Products:</h2>
      <div class="edit-product">
        <div v-if="products.length > 0">
          <table class="table" style="border-collapse: collapse; width: 100%;">
            <thead>
              <tr>
                <th>Product ID</th>
                <th>Name</th>
                <th>Description</th>
                <th>Category</th>
                <th>Price</th> 
                <th>Quantity</th>
                <th>Image</th>
                <th></th>
                <th>Actions</th>
              </tr>
            </thead>
  
            <tbody>
              <tr v-for="product in products" :key="product.id">
                <td>{{ product.id }}</td>
                <td>
                  <span v-if="!product.isEditing">{{ product.name }}</span>
                  <input v-else v-model="product.editedName" />
                </td>
                <td>
                  <span v-if="!product.isEditing">{{ product.description }}</span>
                  <input v-else v-model="product.editedDescription" />
                </td>
                <td>
                    <span v-if="!product.isEditing">{{ product.category.name }}</span>
                    <div v-else class="category-dropdown">
                        <select v-model="product.editedCategory.id" id="category">
                        <option value="" disabled>Select a category</option>
                        <option
                            v-for="category in categories"
                            :key="category.id"
                            :value="category.id"
                        >
                            {{ category.title }}
                        </option>
                        </select>
                        <div class="dropdown-arrow">▼</div> 
                    </div>
                </td>
                <td>
                  <span v-if="!product.isEditing">{{ product.price }}</span>
                  <input class="price" v-else v-model="product.editedPrice" />
                </td>
                <td>
                  <span v-if="!product.isEditing">{{ product.quantity }}</span>
                  <input class="quantity" v-else v-model="product.editedQuantity" />
                </td>
                <td>
                  <img :src="getImageURL(product)" width="30px" />
                </td>
                <td>
                  <input
                    type="file"
                    @change="handleImageUpload(product, $event)"
                    accept="image/*"
                    v-if="product.isEditing"
                  />
                </td>
                <td colspan="2">
                  <button
                    class="btn btn-warning"
                    @click="toggleEdit(product)"
                    v-if="!product.isEditing"
                  >
                    Edit
                  </button>
                  &nbsp;
                  <button
                    class="btn btn-success"
                    @click="saveChanges(product)"
                    v-if="product.isEditing"
                  >
                    Save
                  </button>
                  <button class="btn btn-danger"  @click="confirmDelete(product)">Delete</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </template>
   
  <script>
  import Navbar from "../components/NavbarComponent";
  
  export default {
    name: "EditProduct",
    data() {
      return {
        products: [],
        categories: [],
        message: "",
        messageType: "",
        selectedImage: null,
      };
    },
    components: {
      Navbar,
    },
    mounted() {
      this.fetchProducts();
      this.fetchCategories(); 
    },
    methods: {
      async fetchProducts() {
        try {
          const token = localStorage.getItem("token");
          const response = await fetch("http://localhost:5000/api/products", {
            method: "GET",
            headers: {
              Authorization: "Bearer " + token,
            },
          });
  
          if (response.ok) {
            const data = await response.json();
            this.products = data.map((product) => ({
              ...product,
              isEditing: false,
              editedName: product.name,
              editedDescription: product.description,
              editedPrice: product.price,
              editedQuantity: product.quantity,
              editedCategory: product.category,
              selectedImage: null,
              
            }));
          } else {
            this.message = "Failed to fetch Products.";
            this.messageType = "alert-danger";
            console.error("Failed to fetch Products:", response.status);
          }
        } catch (error) {
          console.error("An error occurred:", error);
          this.message = "An error occurred while fetching Products.";
          this.messageType = "alert-danger";
        }
      },
      async fetchCategories() {
    try {
      const response = await fetch("http://localhost:5000/api/categories");
      if (response.ok) {
        this.categories = await response.json();
      } else {
        console.error("Failed to fetch categories:", response.status);
      }
    } catch (error) {
      console.error("An error occurred while fetching categories:", error);
    }
  },
  
      getImageURL(product) {
        return (
          product.image_filename ||
          "C:\\Users\\DELL\\OneDrive\\Desktop\\mad2_project\\egrocery\\public\\default-image.jpeg"
        );
      },
      handleImageUpload(product, event) {
        const file = event.target.files[0];
        if (file) {
          product.selectedImage = file;
        }
      },
      toggleEdit(product) {
        product.isEditing = !product.isEditing;
      },
  
      async saveChanges(product) {
        try {
          const token = localStorage.getItem("token");
          const productId = product.id;
  
          const formData = new FormData();
          formData.append("name", product.editedName);
          formData.append("description", product.editedDescription);
          formData.append("price", product.editedPrice);
          formData.append("quantity", product.editedQuantity);
          formData.append("category_id", product.editedCategory.id);

          if (product.selectedImage) {
            formData.append(
              "image",
              product.selectedImage,
              product.selectedImage.name
            );
          }
  
          const response = await fetch(
            `http://localhost:5000/store-manager/edit-product/${productId}`,
            {
              method: "PUT",
              headers: {
                Authorization: "Bearer " + token,
              },
              body: formData,
            }
          );
  
          if (response.ok) {
            this.message = "Product updated successfully.";
            this.messageType = "alert-success";
            product.name = product.editedName;
            product.description = product.editedDescription;
            product.category.id = product.editedCategory.id;
            product.price = product.editedPrice;
            product.quantity = product.editedQuantity;
            product.selectedImage = null;
            product.isEditing = false;
            window.location.reload();
          } else {
            this.message = "Failed to update product.";
            this.messageType = "alert-danger";
            console.error("Failed to update product:", response.status);
          }
        } catch (error) {
          console.error("An error occurred:", error);
        }
      },
      async deleteProduct(product) {
        try {
          const token = localStorage.getItem("token");
          const productId = product.id;
  
          const response = await fetch(
            `http://localhost:5000/store-manager/delete-product/${productId}`,
            {
              method: "DELETE",
              headers: {
                Authorization: "Bearer " + token,
              },
            }
          );
  
          if (response.ok) {
            this.message = "Product deleted successfully.";
            this.messageType = "alert-success";
            this.products = this.products.filter((p) => p.id !== productId);
          } else {
            this.message = "Failed to delete product.";
            this.messageType = "alert-danger";
            console.error("Failed to delete product:", response.status);
          }
        } catch (error) {
          console.error("An error occurred:", error);
        }
      },
  
      async confirmDelete(product) {
        const confirmDelete = window.confirm(
          `Are you sure you want to delete the product "${product.name}"?`
        );
  
        if (confirmDelete) {
          this.deleteProduct(product);
        }
      },
    },
  };
  </script>
  
  <style>
  .category-dropdown {
  position: relative;
  display: inline-block;
}

.category-dropdown select {
  padding-right: 30px; 
}

.dropdown-arrow {
  position: absolute;
  top: 50%;
  right: 2px; 
  transform: translateY(-50%);
  pointer-events: none; 
}
.table td {
  padding: 2px; 
  vertical-align: middle; 
}
.price {
  width: 25px; 
  height: 30px; 
}
.quantity {
  width: 30px; 
  height: 30px; 
}
table select {
  width: 100px; 
  height: 30px; 
}

  </style>
  