from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils.text import slugify

from core.applications.inventory.models import AssetTransfer


@receiver(pre_save, sender=AssetTransfer)
def generate_reference(sender, instance, **kwargs):
    if not instance.reference:
        # Generate reference using name and incrementing number
        base_reference = slugify(instance.type)[:10]  # Limit to 10 characters
        print(base_reference, 'reference')
        existing_references = AssetTransfer.objects.filter(reference__startswith=base_reference).values_list(
            'reference', flat=True)
        if existing_references:
            # Get the highest reference number and increment it
            highest_reference_number = max([int(ref[len(base_reference):]) for ref in existing_references])
            instance.reference = f'{base_reference}{highest_reference_number + 1:02}'
        else:
            instance.reference = f'{base_reference}01'
    else:
        print("signal is here")


@receiver(pre_save, sender=AssetTransfer)
def generate_reference(sender, instance, **kwargs):
    print("generating reference")
    if not instance.reference:
        last_reference = AssetTransfer.objects.order_by('-reference').first()
        new_reference = last_reference.reference + 1 if last_reference else 1
        instance.reference = new_reference
