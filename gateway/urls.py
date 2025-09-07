from django.urls import path
from . import views

app_name = 'gateway'

urlpatterns = [
    path('cart/', views.CartView.as_view(), name='cart'),
    path('create-payment-intent/', views.CreatePaymentIntentView.as_view(), name='create_payment_intent'),
    path('webhook/', views.PaymentWebhookView.as_view(), name='payment_webhook'),
    path('orders/', views.OrderHistoryView.as_view(), name='order_history'),
]