<template>
  <v-dialog v-model="dialog" max-width="600">
    <v-card class="cart-dialog">
      <v-toolbar color="light-green" dark>
        <v-btn icon @click="closeCart">
          <v-icon>mdi-close</v-icon>
        </v-btn>
        <v-toolbar-title class="headline">Your Shopping Cart</v-toolbar-title>
      </v-toolbar>
      <v-card-text>
        <v-simple-table>
          <template v-slot:default>
            <thead>
              <tr>
                <th class="product-column">Product</th>
                <th class="name-column">Name</th>
                <th class="id-column">ID</th>
                <th class="quantity-column">Quantity</th>
                <th class="price-column">Price</th>
                <th class="price-column">Total</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(item, index) in plainCartItems" :key="index">

                <td class="product-column">
                  <v-img max-height="50" max-width="50" contain :src="item.product_image"></v-img>
                </td>
                <td class="name-column text-start">{{ item.product_name }}</td>
                <td class="id-column text-start">{{ item.product_id }}</td>
                <td class="quantity-column">{{ item.quantity }}</td>
                <td class="price-column">{{ item.product_price }}</td>
                <td class="price-column">{{ item.product_price * item.quantity  }}</td>
                  <td>
                    <v-btn icon @click="deleteProduct(index)">
                      <v-icon small>mdi-delete</v-icon> 
                    </v-btn>
                  </td>
              </tr>
            </tbody>
          </template>
        </v-simple-table>
      </v-card-text>
      <v-card-text>
        <div class="total-price">
          <span class="total-label">Grand Total:</span>
          <span class="total-amount">{{ calculateGrandTotal() }}</span>
        </div>
      </v-card-text>
      <v-card-actions>
        <v-btn class="remove-button" color="light-red" @click="clearCart">Clear Cart</v-btn>
      </v-card-actions>
      <v-card-actions>
        <v-btn class="buy-all-button" color="light-green" @click="BuyAllProducts">Buy</v-btn>
      </v-card-actions>
      <v-card-actions>
        <v-btn class="close-button" color="light-green" @click="closeCart">Close Cart</v-btn>
      </v-card-actions>
      <v-alert v-if="purchaseSuccess" type="success" dismissible>
        Products purchased successfully.
      </v-alert>
    </v-card>
  </v-dialog>
</template>

<script>
export default {
  props: {
    plainCartItems: Array,
  },
  data() {
    return {
      dialog: false,
      cartItems: [],
      localCartItems: [...this.plainCartItems],
      purchaseSuccess: false,
    };
  },
  created() {
    this.cartItems = [...this.plainCartItems];
  },
  methods: {
    closeCart() {
      this.dialog = false;
    },
    calculateGrandTotal() {
      let total = 0;
      this.plainCartItems.forEach(item => {
        total += item.product_price * item.quantity;
      });
      return total;
    },
    clearCart() {
      this.$emit('clear-cart');  
      this.clearServerCart(); 
    },
    async deleteProduct(index) {
  try {
    const productToDelete = this.plainCartItems[index];
    console.log(productToDelete);
    const response = await fetch("http://localhost:5000/delete-from-cart", {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("token")}`,
      },
      body: JSON.stringify({ product_id: productToDelete.product_id }),
    });

    if (response.ok) {
      const updatedCartItems = [...this.plainCartItems];
      updatedCartItems.splice(index, 1);
      this.$emit("update:plainCartItems", updatedCartItems);
    } else {
      console.error("Failed to delete product from the cart:", response.status);
    }
  } catch (error) {
    console.error("An error occurred while deleting the product from the cart:", error);
  }
},

async clearServerCart() {
  try {
    const token = localStorage.getItem("token");
    if (!token) {
      console.log("Unauthorized user");
      return;
    }

    const response = await fetch("http://localhost:5000/clear-cart", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.ok) {
      console.log("deleted")
}   else {
      console.error("Failed to clear cart on the server:", response.status);
    }
  } catch (error) {
    console.error("An error occurred while clearing the cart on the server:", error);
  }
},
async BuyAllProducts() {
  const token = localStorage.getItem('token');
  console.log(token);
  const purchaseData = this.plainCartItems.map(item => ({
    product_id: item.product_id,
    quantity: item.quantity,
    product_name: item.product_name,
    product_image: item.product_image,
    product_price: item.product_price,
  }));
  console.log('Purchase Data Sent:', purchaseData);

  try {
    const response = await fetch('http://localhost:5000/buy-product', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ cart: purchaseData }),
    });

    if (response.ok) {
      this.cartItems = [];
      this.clearServerCart();
      this.purchaseSuccess = true;
      this.purchaseSuccessMessage = 'Purchase successful!';
      window.location.reload();

    } else {
      console.error('Failed to purchase products:', response.status);
      this.purchaseSuccess = false;
      this.purchaseSuccessMessage = 'An error occurred during purchase. Please try again.';
    }
  } catch (error) {
    console.error('Error during purchase:', error);
  }
},



  },
};
</script>

<style scoped>
.cart-dialog {
  max-width: 600px;
}

.product-column, .name-column, .id-column, .quantity-column {
  text-align: center;
}

.product-column {
  width: 10%;
}

.name-column {
  width: 18%;
}

.id-column {
  width: 5%;
}

.quantity-column {
  width: 10%;
}

.price-column {
  width: 15%;
}

.total-price {
  width: 50%;
  display: flex;
  justify-content: space-between;
  align-items: center; 
  font-weight: bold;
  padding: 10px 0;
  border-top: 1px solid #ccc;
}

.total-label {
  font-size: 18px;
  color: #5fe300; 
}

.total-amount {
  font-size: 18px;
  color: #5fe300; 
}

.close-button {
  width: 100%;
  border-top: 1px solid #ccc;
  border-radius: 0;
  background-color: light-green;
  color: white;
}
</style>

