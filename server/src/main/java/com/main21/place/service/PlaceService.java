package com.main21.place.service;

import com.main21.place.dto.PlaceDto;
import com.main21.place.entity.Place;
import com.main21.place.repository.PlaceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PlaceService {

    private final PlaceRepository placeRepository;

    /*
     * 공간 등록 메서드
     * @param place
     * @return
     */
    public Place createPlace(PlaceDto.Post post) {

        Place place = Place.builder()
                .title(post.getTitle())
                .detailInfo(post.getDetailInfo())
                .maxCapacity(post.getMaxCapacity())
                .address(post.getAddress())
                .charge(post.getCharge())
                .build();

        return placeRepository.save(place);
    }


}
