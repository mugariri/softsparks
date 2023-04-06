from core.applications.inventory.models import AssetTransfer


def asset_transfer_ref_generator(transfer: AssetTransfer):
    count = AssetTransfer.objects.all().count()

    prefix = 'TRANS'

    reference = prefix + str(count+1)
    transfer.reference = reference
    transfer.save()
    return reference

