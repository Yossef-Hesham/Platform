from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
import stripe
from django.conf import settings
from teacher.models import Course
from .models import Cart, CartItem, Order, OrderItem
from .serializers import CartSerializer, OrderSerializer
from student.models import IsStudent, Enrollment


stripe.api_key = settings.STRIPE_SECRET_KEY

class CartView(APIView):
    """Manage shopping cart"""
    permission_classes = [IsStudent]
    
    def get(self, request):
        student = request.user
        cart, created = Cart.objects.get_or_create(student=student)
        return Response(CartSerializer(cart).data)
    
    def post(self, request):
        student = request.user
        course_id = request.data.get('course_id')
        
        course = get_object_or_404(Course, id=course_id)
        cart, created = Cart.objects.get_or_create(student=student)
        
        # Check if course is already in cart
        if CartItem.objects.filter(cart=cart, course=course).exists():
            return Response(
                {'error': 'Course already in cart'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if student is already enrolled
        if student.enrollments.filter(course=course, is_active=True).exists():
            return Response(
                {'error': 'Already enrolled in this course'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        CartItem.objects.create(cart=cart, course=course)
        return Response({'status': 'course added to cart'})
    
    def delete(self, request):
        student = request.user
        course_id = request.data.get('course_id')
        
        cart = get_object_or_404(Cart, student=student)
        cart_item = get_object_or_404(CartItem, cart=cart, course_id=course_id)
        
        cart_item.delete()
        return Response({'status': 'course removed from cart'})

class CreatePaymentIntentView(APIView):
    """Create Stripe payment intent"""
    permission_classes = [IsStudent]
    
    def post(self, request):
        student = request.user
        cart = get_object_or_404(Cart, student=student)
        
        if cart.items.count() == 0:
            return Response(
                {'error': 'Cart is empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate total amount
        total_amount = sum(item.course.price for item in cart.items.all())
        
        # Create payment intent
        try:
            intent = stripe.PaymentIntent.create(
                amount=int(total_amount * 100),  # Convert to cents
                currency='usd',
                metadata={
                    'student_id': student.id,
                    'cart_id': cart.id
                }
            )
            
            # Create order
            order = Order.objects.create(
                student=student,
                total_amount=total_amount,
                stripe_payment_intent_id=intent.id
            )
            
            for item in cart.items.all():
                OrderItem.objects.create(
                    order=order,
                    course=item.course,
                    price=item.course.price
                )
            
            return Response({
                'clientSecret': intent.client_secret,
                'order_id': order.id
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class PaymentWebhookView(APIView):
    """Handle Stripe webhooks for payment confirmation"""
    permission_classes = []  # No authentication for webhooks
    
    def post(self, request):
        payload = request.body
        sig_header = request.META['HTTP_STRIPE_SIGNATURE']
        endpoint_secret = settings.STRIPE_WEBHOOK_SECRET
        
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, endpoint_secret
            )
        except ValueError as e:
            # Invalid payload
            return Response(status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        # Handle the event
        if event.type == 'payment_intent.succeeded':
            payment_intent = event.data.object
            self.handle_payment_succeeded(payment_intent)
        
        return Response(status=status.HTTP_200_OK)
    
    def handle_payment_succeeded(self, payment_intent):
        """Handle successful payment"""
        order = get_object_or_404(
            Order, 
            stripe_payment_intent_id=payment_intent.id
        )
        
        # Update order status
        order.status = 'completed'
        order.save()
        
        # Enroll student in courses
        for item in order.items.all():
            enrollment, created = Enrollment.objects.get_or_create(
                student=order.student,
                course=item.course,
                defaults={'is_active': True}
            )
            
            if not created:
                enrollment.is_active = True
                enrollment.save()
        
        # Clear cart
        cart = Cart.objects.get(student=order.student)
        cart.items.all().delete()

class OrderHistoryView(generics.ListAPIView):
    """View order history"""
    permission_classes = [IsStudent]
    serializer_class = OrderSerializer
    
    def get_queryset(self):
        return Order.objects.filter(student=self.request.user).order_by('-created_at')