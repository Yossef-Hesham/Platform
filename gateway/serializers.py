from rest_framework import serializers
from .models import Cart, CartItem, Order, OrderItem
from teacher.serializers import CourseListSerializer

class CartItemSerializer(serializers.ModelSerializer):
    course = CourseListSerializer(read_only=True)
    course_id = serializers.IntegerField(write_only=True)
    
    class Meta:
        model = CartItem
        fields = ['id', 'course', 'course_id', 'added_at']
        read_only_fields = ['added_at']

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)
    total_items = serializers.SerializerMethodField()
    total_amount = serializers.SerializerMethodField()
    
    class Meta:
        model = Cart
        fields = ['id', 'student', 'items', 'total_items', 'total_amount', 'created_at', 'updated_at']
        read_only_fields = ['student', 'created_at', 'updated_at']
    
    def get_total_items(self, obj):
        return obj.items.count()
    
    def get_total_amount(self, obj):
        return sum(item.course.price for item in obj.items.all())

class OrderItemSerializer(serializers.ModelSerializer):
    course = CourseListSerializer(read_only=True)
    
    class Meta:
        model = OrderItem
        fields = ['id', 'course', 'price']
        read_only_fields = ['course', 'price']

class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    student_name = serializers.ReadOnlyField(source='student.full_name')
    
    class Meta:
        model = Order
        fields = [
            'id', 'order_number', 'student', 'student_name', 'items',
            'total_amount', 'status', 'created_at', 'updated_at',
            'stripe_payment_intent_id'
        ]
        read_only_fields = [
            'order_number', 'student', 'total_amount', 'created_at', 
            'updated_at', 'stripe_payment_intent_id'
        ]

class CreateOrderSerializer(serializers.Serializer):
    cart_id = serializers.IntegerField()
    
    def validate_cart_id(self, value):
        # Check if cart belongs to the current user
        request = self.context.get('request')
        try:
            cart = Cart.objects.get(id=value, student=request.user)
            return value
        except Cart.DoesNotExist:
            raise serializers.ValidationError("Cart not found or doesn't belong to you")

class PaymentIntentSerializer(serializers.Serializer):
    order_id = serializers.IntegerField()
    client_secret = serializers.CharField()
    
    def validate_order_id(self, value):
        # Check if order belongs to the current user
        request = self.context.get('request')
        try:
            order = Order.objects.get(id=value, student=request.user)
            return value
        except Order.DoesNotExist:
            raise serializers.ValidationError("Order not found or doesn't belong to you")